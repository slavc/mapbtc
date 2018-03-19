#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h>

#include "protocol.h"
#include "pack.h"

// FIXME Enable IPv6 back
#define DISABLE_IPV6 true 

#define MAX_WAIT 60 // seconds

uint64_t g_my_nonce;
uint64_t g_peer_count;
uint64_t g_visited_count;
uint64_t g_conn_count;
uint64_t g_max_conn;
bool g_quit = false;

struct peer {
	struct addr {
		int family;
		union {
			struct sockaddr_in in;
			struct sockaddr_in6 in6;
		};
	} addr;
	struct peer *left;
	struct peer *right;
	int epfd; // epoll fd to which this peer belongs
	uint32_t epevents; // epoll event mask
	int conn; // tcp connection socket
	enum {
		DISCONNECTED,
		CONNECTING,
		SENDING_VERSION,
		EXPECTING_VERSION,
		SENDING_MESSAGE,
		EXPECTING_MESSAGE,
		SENDING_VERACK,
		SENDING_GETADDR,
		EXPECTING_ADDR,
	} state;
	struct peer_msg_buf {
		uint8_t *buf;
		size_t size; // size of buffer pointed to by buf
		size_t len; // length of message (to be sent or expected)
		size_t n; // number of bytes transmitted/received
	} in, out;
	// FIXME integrate these bitfields into states?
	struct version version;
	unsigned is_dead:1; // we couldn't connect to it
	unsigned is_visited:1; // we have attempted to connect to it
};

const char *seeds[] = {
	"seed.bitcoin.sipa.be",
	"dnsseed.bluematt.me",
	"dnsseed.bitcoin.dashjr.org",
	"seed.bitcoinstats.com",
	"seed.bitcoin.jonasschnelli.ch",
	"seed.btc.petertodd.org",
};

struct peer *new_peer(int family, const void *addr)
{
	struct peer *peer;

	peer = calloc(1, sizeof(*peer));
	peer->addr.family = family;
	if (family == AF_INET) {
		memcpy(&peer->addr.in, addr, sizeof(struct sockaddr_in));
		peer->addr.in.sin_family = AF_INET;
		peer->addr.in.sin_port = htons(MAINNET_PORT);
	} else {
		memcpy(&peer->addr.in6, addr, sizeof(struct sockaddr_in6));
		peer->addr.in6.sin6_family = AF_INET6;
		peer->addr.in6.sin6_port = htons(MAINNET_PORT);
	}
	peer->conn = -1;
	peer->is_dead = true; // considered is_dead until we successfully connect to it
	return peer;
}

bool add_peer(struct peer **root, struct peer *peer)
{
	if (*root == NULL) {
		*root = peer;
		return true;
	}

	int diff;
	for (struct peer *cur = *root; cur != NULL; /*empty*/) {
		diff = cur->addr.family - peer->addr.family;
		if (diff == 0) {
			if (cur->addr.family == AF_INET) {
				diff = memcmp(&cur->addr.in.sin_addr, &peer->addr.in.sin_addr, 4);
			} else {
				diff = memcmp(&cur->addr.in6.sin6_addr, &peer->addr.in6.sin6_addr, 16);
			}
		}
		if (diff == 0) { // such peer node already exists
			break;
		} else if (diff < 0) {
			if (cur->left == NULL) {
				cur->left = peer;
				return true;
			} else {
				cur = cur->left;
			}
		} else if (diff > 0) {
			if (cur->right == NULL) {
				cur->right = peer;
				return true;
			} else {
				cur = cur->right;
			}
		}
	}
	return false;
}

const char *str_peer(struct peer *peer)
{
	static char addr[INET6_ADDRSTRLEN];
	const void *addr_ptr;

	if (peer->addr.family == AF_INET) {
		addr_ptr = &peer->addr.in.sin_addr;
	} else {
		addr_ptr = &peer->addr.in6.sin6_addr;
	}
	if (inet_ntop(peer->addr.family, addr_ptr, addr, sizeof(addr)) == NULL) {
		warn("inet_ntop");
	}
	return addr;
}

bool walk_peers(struct peer *peer, bool (*fn)(void *, struct peer *), void *arg)
{
	if (peer == NULL) {
		return true;
	}
	if (!walk_peers(peer->left, fn, arg)) {
		return false;
	}
	if (!fn(arg, peer)) {
		return false;
	}
	if (!walk_peers(peer->right, fn, arg)) {
		return false;
	}
	return true;
}

bool print_peer(void *arg, struct peer *peer)
{
	FILE *f = arg;
	if (f == NULL) {
		f = stdout;
	}
	fprintf(f, "%s,%u,%u,%lu,\"%s\",%u\n",
	    str_peer(peer), (unsigned)peer->is_dead,
	    peer->version.protocol, peer->version.services,
	    peer->version.user_agent, peer->version.start_height);
	return true;
}

bool connect_to(struct peer *peer)
{
	int s;
	const struct sockaddr *sa;
	socklen_t sa_len;

       	s = socket(peer->addr.family, SOCK_STREAM, 0);
	if (s == -1) {
		warn("socket %d", errno);
		return false;
	}

	if (fcntl(s, F_SETFL, O_NONBLOCK) != 0) {
		warn("fcntl O_NONBLOCK: %d", errno);
		return false;
	}

	if (peer->addr.family == AF_INET) {
		sa = (const struct sockaddr *)&peer->addr.in;
		sa_len = sizeof(peer->addr.in);
	} else {
		sa = (const struct sockaddr *)&peer->addr.in6;
		sa_len = sizeof(peer->addr.in6);
	}

	if (connect(s, sa, sa_len) != 0 && errno != EINPROGRESS) {
		warn("connect %d", errno);
		close(s);
		return false;
	}
	peer->conn = s;
	peer->state = CONNECTING;
	return true;
}

void add_to_poll(struct peer *peer, int epfd)
{
	struct epoll_event ev;

	peer->epfd = epfd;
	peer->epevents = ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
	ev.data.ptr = peer;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, peer->conn, &ev) != 0) {
		err(1, "epoll_ctl add");
	}
}

bool query_more_peers(void *arg, struct peer *peer)
{
	if (peer->is_visited) {
		return true;
	}
	peer->is_visited = true;
	g_visited_count++;

	if (!connect_to(peer)) {
		printf("%s: failed to connect to peer, marking as dead\n", str_peer(peer));
		peer->is_dead = true;
		return true;
	}

	int epfd = *(int *)arg;
	add_to_poll(peer, epfd);

	if (++g_conn_count >= g_max_conn) {
		return false;
	} else {
		return true;
	}
}

void poll_out(struct peer *peer, bool enable)
{
	struct epoll_event ev;

	if (enable == true) {
		ev.events = peer->epevents | EPOLLOUT;
	} else {
		ev.events = peer->epevents & ~EPOLLOUT;
	}
	ev.data.ptr = peer;
	if (epoll_ctl(peer->epfd, EPOLL_CTL_MOD, peer->conn, &ev) != 0) {
		err(1, "epoll_ctl");
	}
}

void poll_in(struct peer *peer, bool enable)
{
	struct epoll_event ev;

	if (enable == true) {
		ev.events = peer->epevents | EPOLLIN;
	} else {
		ev.events = peer->epevents & ~EPOLLIN;
	}
	ev.data.ptr = peer;
	if (epoll_ctl(peer->epfd, EPOLL_CTL_MOD, peer->conn, &ev) != 0) {
		err(1, "epoll_ctl");
	}
}

bool send_msg(struct peer *peer)
{
	if (peer->out.buf == NULL || peer->out.len == 0) {
		return false;
	}

	if (peer->out.n == peer->out.len) {
		return true;
	}

	void *ptr = peer->out.buf + peer->out.n;
	size_t rem = peer->out.len - peer->out.n;
	ssize_t n = write(peer->conn, ptr, rem);

	if (n < 0) {
		warn("send_msg write");
		return false;
	} else if ((size_t)n == rem) {
		poll_out(peer, false);
		return true;
	} else {
		peer->out.n += n;
		return false;
	}
}

bool recv_msg(struct peer *peer, ssize_t *out_n)
{
	if (peer->in.buf == NULL) {
		return false;
	}

	if (peer->in.len != 0 && peer->in.n == peer->in.len) {
		return true;
	}

	if (peer->in.n < HDR_SIZE) {
		void *ptr = peer->in.buf + peer->in.n;
		size_t rem = HDR_SIZE - peer->in.n;
		ssize_t n = read(peer->conn, ptr, rem);
		*out_n = n;
		if (n < 0) {
			// FIXME close connection?
			warn("recv_msg read");
			return false;
		} else if ((size_t)n < rem) {
			peer->in.n += n;
			return false;
		} else {
			// finished reading header
			peer->in.n += n;
			uint32_t i;
			unpack32(&i, peer->in.buf + HDR_PAYLOAD_SIZE_OFF, peer->in.n - HDR_PAYLOAD_SIZE_OFF);
			peer->in.len = i;
			peer->in.len += HDR_SIZE;
			if (peer->in.len > MAX_MSG_SIZE) {
				printf("%s: payload size exceeds maximum, disconnecting...", str_peer(peer));
				*out_n = 0;
				return false;
			}
			if (peer->in.len > peer->in.size) {
				peer->in.size = peer->in.len;
				peer->in.buf = realloc(peer->in.buf, peer->in.size);
			}
		}
	}

	void *ptr = peer->in.buf + peer->in.n;
	size_t rem = peer->in.len - peer->in.n;
	ssize_t n = read(peer->conn, ptr, rem);
	*out_n = n;
	if (n < 0) {
		warn("recv_msg read");
		return false;
	} else {
		peer->in.n += n;
		if (peer->in.n == peer->in.len) {
			peer->in.n = 0;
			peer->in.len = 0;
			return true;
		} else {
			return false;
		}
	}
}

void disconnect_from(struct peer *peer)
{
	if (epoll_ctl(peer->epfd, EPOLL_CTL_DEL, peer->conn, NULL) == -1) {
		err(1, "epoll_ctl del");
	}
	(void)close(peer->conn);
	peer->conn = -1;
	peer->state = DISCONNECTED;
}

void start_send_version_msg(struct peer *peer)
{
	peer->out.n = 0;
	peer->out.len = pack_version_msg(peer->out.buf, peer->out.size, &g_my_nonce);
	peer->state = SENDING_VERSION;
}


void start_send_verack_msg(struct peer *peer)
{
	peer->out.n = 0;
	peer->out.len = pack_verack_msg(peer->out.buf, peer->out.size);
	peer->state = SENDING_VERACK;
	poll_out(peer, true);
}

void start_send_getaddr_msg(struct peer *peer)
{
	peer->out.n = 0;
	peer->out.len = pack_getaddr_msg(peer->out.buf, peer->out.size);
	peer->state = SENDING_GETADDR;
	poll_out(peer, true);
}

bool is_ipv4_addr(const void *a)
{
	return memcmp(a, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 10) == 0
	    && memcmp((const uint8_t *)a + 10, "\xff\xff", 2) == 0;
}

void set_max_conn(void)
{
	struct rlimit rlim;
	int open_count;
	long rc;

	for (open_count = 0; fcntl(open_count, F_GETFD, NULL) != -1; open_count++) {
		/* empty */
	}

	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		g_max_conn = rlim.rlim_cur - open_count - 2;
	} else if ((rc = sysconf(_SC_OPEN_MAX)) > 0) {
		g_max_conn = rc - open_count - 2;
	} else {
		g_max_conn = _POSIX_OPEN_MAX - open_count - 2;
	}
}

void sighandler(int sig)
{
	(void)sig;
	g_quit = true;
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	if (signal(SIGINT, sighandler) == SIG_ERR || signal(SIGTERM, sighandler) == SIG_ERR) {
		err(1, "signal");
	}

	struct peer *peers = NULL;

	srand(time(NULL));
	g_my_nonce = ((uint64_t)rand() << 32) | (uint64_t)rand();

	set_max_conn();

	int epfd = epoll_create(1);
	if (epfd == -1) {
		err(1, "epoll_create");
	}

	FILE *peers_graph = fopen("peers_graph.csv", "w");
	if (peers_graph == NULL) {
		err(1, "failed to open peers log file");
	}
	fprintf(peers_graph, "DstNode,SrcNode\n");

	/*
	 * Query the seed domain names for initial peers.
	 */

	for (size_t i = 0; i < NELEMS(seeds); i++) {
		struct addrinfo *result;
		struct addrinfo *ai;

		int error = getaddrinfo(seeds[i], NULL, NULL, &result);
		if (error) {
			warnx("getaddrinfo %s failed", seeds[i]);
			continue;
		}

		printf("Adding peers from seed %s...\n", seeds[i]);
		for (ai = result; ai != NULL; ai = ai->ai_next) {
			if (DISABLE_IPV6 && ai->ai_family != AF_INET) {
				continue;
			}
			if (ai->ai_protocol != IPPROTO_TCP) {
				continue;
			}
			if (ai->ai_socktype != SOCK_STREAM) {
				continue;
			}
			struct peer *peer = new_peer(ai->ai_family, ai->ai_addr);
			fprintf(peers_graph, "%s,%s\n", str_peer(peer), seeds[i]);
			if (!add_peer(&peers, peer)) {
				// we already have this peer
				free(peer);
			} else {
				g_peer_count++;
			}
		}

		freeaddrinfo(result);
	}

	/*
	 * Connect to the initial peers we got from seed domain names and query
	 * them for more peers, and query those peers for even more peers, and
	 * so on.
	 */

	walk_peers(peers, query_more_peers, &epfd);
	while (!g_quit) {
		sigset_t sigmask;
		if (sigemptyset(&sigmask) == -1) {
			err(1, "sigemptyset");
		}
		if (sigaddset(&sigmask, SIGINT) == -1) {
			err(1, "sigaddset");
		}
		if (sigaddset(&sigmask, SIGTERM) == -1) {
			err(1, "sigaddset");
		}

		struct epoll_event ev;
		int n = epoll_pwait(epfd, &ev, 1, MAX_WAIT*1000, &sigmask);
		if (n < 0) {
			if (errno == EINTR) {
				printf("interrupted\n");
				break;
			}
			warnx("epoll_wait");
			continue;
		}
		if (n == 0) {
			// nothing happened in MAX_WAIT seconds - give up
			printf("no activity in %d seconds, exiting\n", MAX_WAIT);
			break;
		}

		struct peer *peer = ev.data.ptr;
		int optval;
		socklen_t optlen;
		int rc;
		ssize_t n_recv;
		if (ev.events & EPOLLOUT) {
			optlen = sizeof(optval);
			rc = getsockopt(peer->conn, SOL_SOCKET, SO_ERROR, &optval, &optlen); 
			if (rc == -1 || optval != 0) {
				printf("%s: connection failed...\n", str_peer(peer));
				disconnect_from(peer);
				peer->is_dead = true;
				if (--g_conn_count < g_max_conn && g_visited_count < g_peer_count) {
					walk_peers(peers, query_more_peers, &epfd);
				}
				continue;
			} else {
				printf("%s: connected to peer\n", str_peer(peer));
			}

			// we've connected to a peer or can continue sneding a message
			switch (peer->state) {
			case CONNECTING:

				peer->is_dead = false;

				peer->in.size = 1024;
				peer->in.buf = malloc(peer->in.size);
				peer->in.len = 0;
				peer->in.n = 0;

				peer->out.size = 512;
				peer->out.buf = malloc(peer->out.size);
				peer->out.len = 0;
				peer->out.n = 0;

				start_send_version_msg(peer);

				break;

			case SENDING_VERSION:
				if (send_msg(peer)) {
					peer->state = EXPECTING_VERSION;
				}
				break;

			case SENDING_VERACK:
				if (send_msg(peer)) {
					// finished sending verack message, now send getaddr
					start_send_getaddr_msg(peer);
				}
				break;

			case SENDING_GETADDR:
				if (send_msg(peer)) {
					peer->state = EXPECTING_ADDR;
				}
				break;

			default:
				break;
			}
		} else if (ev.events & EPOLLIN) {
			// we've received a piece of message from one of the peers
			if (recv_msg(peer, &n_recv)) {
				struct hdr hdr;
				if (!parse_hdr(peer->in.buf, peer->in.size, &hdr)) {
					printf("%s: received message with invalid header, disconnecting...\n", str_peer(peer));
					disconnect_from(peer);
					if (--g_conn_count < g_max_conn && g_visited_count < g_peer_count) {
						walk_peers(peers, query_more_peers, &epfd);
					}
				} else {
					switch (peer->state) {
					case EXPECTING_VERSION:
						if (parse_version_msg(peer->in.buf, peer->in.size, &peer->version)) {
							start_send_verack_msg(peer);
						} else {
							printf("%s: received inavalid version message, disconnecting...\n", str_peer(peer));
							disconnect_from(peer);
							if (--g_conn_count < g_max_conn && g_visited_count < g_peer_count) {
								walk_peers(peers, query_more_peers, &epfd);
							}
						}
						break;

					case EXPECTING_ADDR:
						if (is_addr_msg(&hdr)) {
							uint8_t *msg = peer->in.buf + HDR_SIZE;
							size_t msg_len = hdr.payload_size;

							// FIXME parse message into a data structure?

							uint64_t num_recs;
							size_t rec_off;

							if (!(rec_off = unpack_cuint(&num_recs, msg, msg_len))) {
								printf("%s: failed to parse the number of records in addr message, disconnecting...\n", str_peer(peer));
								disconnect_from(peer);
								if (--g_conn_count < g_max_conn && g_visited_count < g_peer_count) {
									walk_peers(peers, query_more_peers, &epfd);
								}
								break;
							}

							if ((uint64_t)num_recs * (uint64_t)ADDR_REC_SIZE + rec_off > msg_len) {
								printf("%s: invalid number of records in addr message, disconnecting...\n", str_peer(peer));
								disconnect_from(peer);
								if (--g_conn_count < g_max_conn && g_visited_count < g_peer_count) {
									walk_peers(peers, query_more_peers, &epfd);
								}
								break;
							}

							for (uint16_t i = 0; i < num_recs; i++) {
								size_t off = rec_off + i*ADDR_REC_SIZE + ADDR_IP_OFF;
								struct sockaddr_in sin;
								struct sockaddr_in6 sin6;
								void *addr_ptr;
								int addr_family;
								if (is_ipv4_addr(msg + off)) {
									addr_family = AF_INET;
									sin.sin_family = AF_INET;
									addr_ptr = &sin;
									memcpy(&sin.sin_addr, msg + off + 12, 4);
								} else if (DISABLE_IPV6) {
									continue;
								} else {
									addr_family = AF_INET6;
									sin6.sin6_family = AF_INET6;
									addr_ptr = &sin6;
									memcpy(&sin6.sin6_addr, msg + off, 16);
								}
								struct peer *peer_rec = new_peer(addr_family, addr_ptr);
								fprintf(peers_graph, "%s,", str_peer(peer_rec));
								fprintf(peers_graph, "%s\n", str_peer(peer));
								if (!add_peer(&peers, peer_rec)) {
									// we already have this peer
									free(peer_rec);
									continue;
								} else {
									g_peer_count++;
									printf("%s: adding new peer ", str_peer(peer));
									printf("%s...\n", str_peer(peer_rec));
								}
							}

							disconnect_from(peer);
							printf("%s: done getting peers, disconnecting...\n", str_peer(peer));
							if (--g_conn_count < g_max_conn && g_visited_count < g_peer_count) {
								walk_peers(peers, query_more_peers, &epfd);
							}
						}
						break;

					default:
						printf("%s: received an unexpected message, ignoring\n", str_peer(peer));
					}
				}
			} else if (n_recv == 0) {
				// peer closed connection
				printf("%s: peer closed connection...\n", str_peer(peer));
				disconnect_from(peer);
				if (--g_conn_count < g_max_conn && g_visited_count < g_peer_count) {
					walk_peers(peers, query_more_peers, &epfd);
				}
			}
		} else if (ev.events & (EPOLLERR | EPOLLRDHUP)) {
			printf("%s: connection error, disconnecting...\n", str_peer(peer));
			disconnect_from(peer);
			if (--g_conn_count < g_max_conn && g_visited_count < g_peer_count) {
				walk_peers(peers, query_more_peers, &epfd);
			}
			peer->is_dead = true;
		}
	}

	fclose(peers_graph);

	// FIXME use sqlite to record data about peers?
	FILE *peers_csv = fopen("peers.csv", "w");
	if (peers_csv == NULL) {
		err(1, "failed to open peers csv file");
	}
	fprintf(peers_csv, "IP,Alive,Protocol,Services,UserAgent,StartHeight\n");
	walk_peers(peers, print_peer, peers_csv);
	fclose(peers_csv);

	return 0;
}
