/*
 * Copyright (c) 2018 Sviatoslav Chagaev <sviatoslav.chagaev@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/queue.h>
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include <limits.h>
#include <search.h>

#include "protocol.h"
#include "pack.h"

#define MAX_WAIT 90 // seconds; max peer inactivity before disconnecting from it
#define MAX_EPOLL_EVENTS 2000 // max number of events epoll will report
#define MAX_CONN_LIMIT 60000 // max concurrent connections if nofiles ulimit is not set

struct peer {
	struct in6_addr addr;
	struct timespec timeout;
	struct peer *next;
	TAILQ_ENTRY(peer) conn_list_entry;
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
	struct version version;
	unsigned is_dead:1; // we couldn't connect to it
};

bool g_verbose = false;
bool g_no_ipv6 = false;
uint64_t g_my_nonce;
uint64_t g_conn_count;
uint64_t g_max_conn;
struct peer *g_connect_queue;
int g_epoll_fd;
bool g_quit = false;
FILE *g_peer_graph_file;
FILE *g_peer_file;
FILE *g_log_stream;
void *g_known_ip_addr_tree;
TAILQ_HEAD(conn_list, peer) g_connections = TAILQ_HEAD_INITIALIZER(g_connections);

const char *seeds[] = {
	"seed.bitcoin.sipa.be",
	"dnsseed.bluematt.me",
	"dnsseed.bitcoin.dashjr.org",
	"seed.bitcoinstats.com",
	"seed.bitcoin.jonasschnelli.ch",
	"seed.btc.petertodd.org",
};

void print_debug(const char *fmt, ...)
{
	if (!g_verbose) {
		return;
	}
	va_list ap;
	fprintf(g_log_stream, "debug: ");
	va_start(ap, fmt);
	vfprintf(g_log_stream, fmt, ap);
	va_end(ap);
	fprintf(g_log_stream, "\n");
}

void print_warning(const char *fmt, ...)
{
	va_list ap;
	fprintf(g_log_stream, "warning: ");
	va_start(ap, fmt);
	vfprintf(g_log_stream, fmt, ap);
	va_end(ap);
	fprintf(g_log_stream, "\n");
}

void print_error(const char *fmt, ...)
{
	va_list ap;
	fprintf(g_log_stream, "error: ");
	va_start(ap, fmt);
	vfprintf(g_log_stream, fmt, ap);
	va_end(ap);
	fprintf(g_log_stream, "\n");
}

struct timespec get_time(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t) == -1) {
		print_error("clock_gettime: errno %d", errno);
		exit(EXIT_FAILURE);
	}
	return t;
}

void update_timeout(struct peer *peer)
{
	peer->timeout = get_time();
	peer->timeout.tv_nsec = 0;
	peer->timeout.tv_sec += MAX_WAIT;
}

int get_epoll_timeout(struct peer *peer)
{
	struct timespec t = get_time();
	t.tv_nsec = 0;
	if (peer->timeout.tv_sec < t.tv_sec) {
		return 0;
	}
	return (int)(peer->timeout.tv_sec - t.tv_sec)*1000;
}

struct peer *new_peer(int family, const void *sa)
{
	struct peer *peer;

	peer = calloc(1, sizeof(*peer));
	if (family == AF_INET) {
		memset(&peer->addr, 0, 10);
		memset((uint8_t *)&peer->addr + 10, 0xff, 2);
		memcpy((uint8_t *)&peer->addr + 12, &((struct sockaddr_in *)sa)->sin_addr, sizeof(peer->addr));
	} else {
		memcpy(&peer->addr, &((struct sockaddr_in6 *)sa)->sin6_addr, sizeof(peer->addr));
	}
	peer->conn = -1;
	peer->is_dead = true; // considered dead until we successfully connect to it
	return peer;
}

const char *str_peer(struct peer *peer)
{
	static char str_addr[INET6_ADDRSTRLEN] = "";
	if (inet_ntop(AF_INET6, &peer->addr, str_addr, sizeof(str_addr)) == NULL) {
		print_warning("inet_ntop: errno %d", errno);
	}
	return str_addr;
}

bool print_peer(FILE *f, struct peer *peer)
{
	if (f == NULL) {
		f = stdout;
	}
	fprintf(f, "%s,%u,%u,%lu,\"%s\",%u\n",
	    str_peer(peer), (unsigned)!peer->is_dead,
	    peer->version.protocol, peer->version.services,
	    peer->version.user_agent, peer->version.start_height);
	return true;
}

bool is_ipv4_mapped(const void *a)
{
	return memcmp(a, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 10) == 0
	    && memcmp((const uint8_t *)a + 10, "\xff\xff", 2) == 0;
}

bool is_peer_on_conn_list(struct peer *peer)
{

	return peer->conn_list_entry.tqe_prev != NULL
	    || peer->conn_list_entry.tqe_next != NULL;
}

bool connect_to(struct peer *peer)
{
	int s;
	int family;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr *sa;
	socklen_t sa_len;

	if (is_ipv4_mapped(&peer->addr)) {
		family = AF_INET;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(MAINNET_PORT);
		memcpy(&sin.sin_addr, (uint8_t *)&peer->addr + 12, 4);
		sa = (void *)&sin;
		sa_len = sizeof(sin);
	} else {
		family = AF_INET6;
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(MAINNET_PORT);
		memcpy(&sin6.sin6_addr, &peer->addr, 16);
		sa = (void *)&sin6;
		sa_len = sizeof(sin6);
	}

	s = socket(family, SOCK_STREAM, 0);
	if (s == -1) {
		int errno_copy = errno;
		print_warning("%s: socket: errno %d", str_peer(peer), errno_copy);
		return false;
	}

	if (fcntl(s, F_SETFL, O_NONBLOCK) != 0) {
		int errno_copy = errno;
		print_warning("%s: fcntl O_NONBLOCK: errno %d", str_peer(peer), errno_copy);
		close(s);
		return false;
	}

	if (connect(s, sa, sa_len) != 0 && errno != EINPROGRESS) {
		int errno_copy = errno;
		print_warning("%s: connect: errno %d", str_peer(peer), errno_copy);
		close(s);
		return false;
	}
	peer->conn = s;
	peer->state = CONNECTING;
	return true;
}

void add_to_poll(struct peer *peer)
{
	struct epoll_event ev;

	peer->epevents = ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
	ev.data.ptr = peer;
	if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, peer->conn, &ev) != 0) {
		int errno_copy = errno;
		print_error("epoll_ctl add: errno %d", str_peer(peer), errno_copy);
		exit(EXIT_FAILURE);
	}
}

struct peer *pop_connect_queue(void)
{
	struct peer *peer = NULL;
	if (g_connect_queue != NULL) {
		peer = g_connect_queue;
		g_connect_queue = peer->next;
	}
	return peer;
}

void push_connect_queue(struct peer *peer)
{
	peer->next = g_connect_queue;
	g_connect_queue = peer;
}

void query_more_peers(void)
{
	struct peer *peer;
	while (g_conn_count < g_max_conn && (peer = pop_connect_queue()) != NULL) {
		if (!connect_to(peer)) {
			print_debug("%s: failed to connect to peer, marking as dead", str_peer(peer));
			peer->is_dead = true;
			print_peer(g_peer_file, peer);
			free(peer);
		} else {
			print_debug("trying to connect to %s...", str_peer(peer));
			g_conn_count++;
			add_to_poll(peer);
		}
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
	if (epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, peer->conn, &ev) != 0) {
		int errno_copy = errno;
		print_error("%s: epoll_ctl: errno %d", str_peer(peer), errno_copy);
		exit(EXIT_FAILURE);
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
	if (epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, peer->conn, &ev) != 0) {
		int errno_copy = errno;
		print_error("%s: epoll_ctl: errno %d", str_peer(peer), errno_copy);
		exit(EXIT_FAILURE);
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
		if (errno != EAGAIN) {
			int errno_copy = errno;
			print_warning("%s: send_msg write: errno %d", str_peer(peer), errno_copy);
		}
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
			if (errno != EAGAIN) {
				int errno_copy = errno;
				print_warning("%s: recv_msg read: errno %d", str_peer(peer), errno_copy);
			}
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
				print_debug("%s: payload size exceeds maximum, disconnecting...", str_peer(peer));
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
		if (errno != EAGAIN) {
			int errno_copy = errno;
			print_warning("%s: recv_msg read: errno %d", str_peer(peer), errno_copy);
		}
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
	if (epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, peer->conn, NULL) == -1) {
		int errno_copy = errno;
		print_error("%s: epoll_ctl del: errno %d", str_peer(peer), errno_copy);
		exit(EXIT_FAILURE);
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

void set_max_conn(void)
{
	struct rlimit rlim;
	int open_count;
	long rc;

	for (open_count = 0; fcntl(open_count, F_GETFD, NULL) != -1; open_count++) {
		/* empty */
	}

	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		if (rlim.rlim_cur == RLIM_INFINITY) {
			g_max_conn = MAX_CONN_LIMIT;
		} else {
			g_max_conn = rlim.rlim_cur - open_count;
		}
	} else if ((rc = sysconf(_SC_OPEN_MAX)) > 0) {
		g_max_conn = rc - open_count;
	} else {
		g_max_conn = _POSIX_OPEN_MAX - open_count;
	}
}

void sighandler(int sig)
{
	(void)sig;
	g_quit = true;
}

int ip_cmp(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(struct in6_addr));
}

bool is_known_peer(struct in6_addr *ip)
{
	struct in6_addr *ip_copy = malloc(sizeof(*ip));
	memcpy(ip_copy, ip, sizeof(*ip));

	struct in6_addr **node = tsearch(ip_copy, &g_known_ip_addr_tree, ip_cmp);
	if (*node == ip_copy) {
		return false;
	} else {
		// we already have this IP in the tree
		free(ip_copy);
		return true;
	}
}

void finalize_peer(struct peer *peer)
{
	if (is_peer_on_conn_list(peer)) {
		TAILQ_REMOVE(&g_connections, peer, conn_list_entry);
	}
	disconnect_from(peer);
	g_conn_count--;
	print_peer(g_peer_file, peer);
	free(peer->in.buf);
	free(peer->out.buf);
	free(peer);
}

void set_sigmask(sigset_t *sigmask)
{
	if (sigemptyset(sigmask) == -1) {
		print_error("sigemptyset: errno %d", errno);
		exit(EXIT_FAILURE);
	}
	if (sigaddset(sigmask, SIGINT) == -1) {
		print_error("sigaddset: errno %d", errno);
		exit(EXIT_FAILURE);
	}
	if (sigaddset(sigmask, SIGTERM) == -1) {
		print_error("sigaddset: errno %d", errno);
		exit(EXIT_FAILURE);
	}
}

void open_output_files(void)
{
	g_peer_graph_file = fopen("peer_graph.csv", "w");
	if (g_peer_graph_file == NULL) {
		print_error("failed to open peers log file: errno %d", errno);
		exit(EXIT_FAILURE);
	}
	fprintf(g_peer_graph_file, "DstNode,SrcNode\n");

	g_peer_file = fopen("peers.csv", "w");
	if (g_peer_file == NULL) {
		print_error("failed to open peers csv file: errno %d", errno);
		exit(EXIT_FAILURE);
	}
	fprintf(g_peer_file, "IP,MainnetPortOpen,Protocol,Services,UserAgent,StartHeight\n");
}

void close_output_files(void)
{
	fclose(g_peer_graph_file);
	fclose(g_peer_file);
}

bool handle_pollout(struct peer *peer)
{
	// we've connected to a peer or can continue sneding a message
	switch (peer->state) {
	case CONNECTING:
		print_debug("%s: connected to peer", str_peer(peer));

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

	return true;
}

bool handle_pollin(struct peer *peer)
{
	// we've received a piece of message from one of the peers
	ssize_t n_recv = 0;
	bool have_complete_msg;

	have_complete_msg = recv_msg(peer, &n_recv);

	if (!have_complete_msg) {
		if (n_recv == 0) {
			// peer closed connection
			print_debug("%s: peer closed connection...", str_peer(peer));
			finalize_peer(peer);
			return false;
		}
		return true;
	}

	struct hdr hdr;
	if (!parse_hdr(peer->in.buf, peer->in.size, &hdr)) {
		print_debug("%s: received message with invalid header, disconnecting...", str_peer(peer));
		finalize_peer(peer);
		return false;
	}

	if (peer->state == EXPECTING_VERSION) {
		if (parse_version_msg(peer->in.buf, peer->in.size, &peer->version)) {
			start_send_verack_msg(peer);
		} else {
			print_debug("%s: received invalid version message, disconnecting...", str_peer(peer));
			finalize_peer(peer);
			return false;
		}
	} else if (peer->state == EXPECTING_ADDR) {
		if (!is_addr_msg(&hdr)) {
			return true;
		}

		uint8_t *msg = peer->in.buf + HDR_SIZE;
		size_t msg_len = hdr.payload_size;

		uint64_t num_recs;
		size_t rec_off;

		if (!(rec_off = unpack_cuint(&num_recs, msg, msg_len))) {
			print_debug("%s: failed to parse the number of records in addr message, disconnecting...", str_peer(peer));
			finalize_peer(peer);
			return false;
		}

		if ((uint64_t)num_recs * (uint64_t)ADDR_REC_SIZE + rec_off > msg_len) {
			print_debug("%s: invalid number of records in addr message, disconnecting...", str_peer(peer));
			finalize_peer(peer);
			return false;
		}

		for (uint16_t i = 0; i < num_recs; i++) {
			size_t off = rec_off + i*ADDR_REC_SIZE + ADDR_IP_OFF;
			struct in6_addr *addr = (void *)(msg + off);
			struct sockaddr_in sin;
			struct sockaddr_in6 sin6;
			void *addr_ptr;
			int addr_family;
			if (is_ipv4_mapped(msg + off)) {
				addr_family = AF_INET;
				sin.sin_family = AF_INET;
				addr_ptr = &sin;
				memcpy(&sin.sin_addr, msg + off + 12, 4);
			} else if (g_no_ipv6) {
				continue;
			} else {
				addr_family = AF_INET6;
				sin6.sin6_family = AF_INET6;
				addr_ptr = &sin6;
				memcpy(&sin6.sin6_addr, msg + off, 16);
			}
			if (!is_known_peer(addr)) {
				struct peer *peer_rec = new_peer(addr_family, addr_ptr);
				fprintf(g_peer_graph_file, "%s,", str_peer(peer_rec));
				fprintf(g_peer_graph_file, "%s\n", str_peer(peer));
				print_debug("%s: adding new peer:", str_peer(peer));
				print_debug("    %s", str_peer(peer_rec));
				push_connect_queue(peer_rec);
			}
		}

		print_debug("%s: done getting peers, disconnecting...", str_peer(peer));
		finalize_peer(peer);
	}
	return false;
}

bool handle_epoll_event(struct epoll_event *ev)
{
	struct peer *peer;
	int rc;
	int optval;
	socklen_t optlen;

	peer = ev->data.ptr;

	optlen = sizeof(optval);
	rc = getsockopt(peer->conn, SOL_SOCKET, SO_ERROR, &optval, &optlen); 
	if (rc == -1 || optval != 0) {
		print_debug("%s: connection failed, rc=%d, SO_ERROR=%d...", str_peer(peer), rc, optval);
		finalize_peer(peer);
		return false;
	}

	if (ev->events & EPOLLOUT) {
		print_debug("%s: EPOLLOUT event", str_peer(peer));
		return handle_pollout(peer);
	} else if (ev->events & EPOLLIN) {
		print_debug("%s: EPOLLIN event", str_peer(peer));
		return handle_pollin(peer);
	} else /*if (ev->events & (EPOLLERR | EPOLLRDHUP))*/ {
		print_debug("%s: EPOLLERR or EPOLLRDHUP event, disconnecting...", str_peer(peer));
		peer->is_dead = true;
		finalize_peer(peer);
		return false;
	}
}

bool is_timed_out(struct peer *peer)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t) == -1) {
		int errno_copy = errno;
		print_error("%s: clock_gettime: errno %d", str_peer(peer), errno_copy);
		exit(EXIT_FAILURE);
	}
	return t.tv_sec >= peer->timeout.tv_sec;
}

void mainloop(void)
{
	sigset_t sigmask;
	struct epoll_event events[MAX_EPOLL_EVENTS];
	int num_events;
	int timeout;
	struct peer *peer;

	while (!g_quit && (g_conn_count > 0 || g_connect_queue != NULL)) {
		print_debug("%lu connections", (long unsigned)g_conn_count);

		query_more_peers();

		if (!TAILQ_EMPTY(&g_connections)) {
			peer = TAILQ_FIRST(&g_connections);
			timeout = get_epoll_timeout(peer);
			print_debug("using epoll timeout %d ms from peer %s", timeout, str_peer(peer));
		} else {
			timeout = -1;
		}

		set_sigmask(&sigmask);
		num_events = epoll_pwait(g_epoll_fd, events, MAX_EPOLL_EVENTS, timeout, &sigmask);
		if (num_events < 0) {
			if (errno == EINTR) {
				print_debug("interrupted");
				break;
			}
			print_warning("epoll_wait: errno %d", errno);
			continue;
		}
		if (num_events == 0) {
			while (!TAILQ_EMPTY(&g_connections)) {
				peer = TAILQ_FIRST(&g_connections);
				if (is_timed_out(peer)) {
					print_debug("%s: timed out, disconnecting...", str_peer(peer));
					finalize_peer(peer);
				} else {
					break;
				}
			}
			continue;
		}
		print_debug("processing %d events", num_events);
		for (int i = 0; i < num_events; i++) {
			if (handle_epoll_event(&events[i])) {
				// all ok, we'll be continuing talking to this peer,
				// so update it's timeout and reinsert it at the tail of the timeout list
				peer = events[i].data.ptr;
				update_timeout(peer);
				if (is_peer_on_conn_list(peer)) {
					// this peer is already on the list, need to remove first
					TAILQ_REMOVE(&g_connections, peer, conn_list_entry);
				}
				TAILQ_INSERT_TAIL(&g_connections, peer, conn_list_entry);
			}
		}
	}
}

void get_initial_peers(void)
{
	for (size_t i = 0; i < NELEMS(seeds); i++) {
		struct addrinfo *result;
		struct addrinfo *ai;

		int error = getaddrinfo(seeds[i], NULL, NULL, &result);
		if (error) {
			print_warning("getaddrinfo %s failed: errno %d", seeds[i], errno);
			continue;
		}

		print_debug("adding peers from seed %s...", seeds[i]);
		for (ai = result; ai != NULL; ai = ai->ai_next) {
			if (ai->ai_protocol != IPPROTO_TCP) {
				continue;
			}
			if (ai->ai_socktype != SOCK_STREAM) {
				continue;
			}
			struct in6_addr addr;
			if (ai->ai_family == AF_INET) {
				struct sockaddr_in *sin = (void *)ai->ai_addr;
				// make an IPv4-mapped IPv6-address
				memset(&addr, 0, 10);
				memset((uint8_t *)&addr + 10, 0xff, 2);
				memcpy((uint8_t *)&addr + 12, &sin->sin_addr, 4);
			} else if (ai->ai_family == AF_INET6) {
				if (g_no_ipv6) {
					continue;
				}
				struct sockaddr_in6 *sin6 = (void *)ai->ai_addr;
				memcpy(&addr, &sin6->sin6_addr, sizeof(addr));
			} else {
				continue;
			}
			if (!is_known_peer(&addr)) {
				struct peer *peer = new_peer(ai->ai_family, ai->ai_addr);
				fprintf(g_peer_graph_file, "%s,%s\n", str_peer(peer), seeds[i]);
				push_connect_queue(peer);
			}
		}

		freeaddrinfo(result);
	}
}

void init_program(void)
{
	g_log_stream = stdout;

	if (signal(SIGINT, sighandler) == SIG_ERR || signal(SIGTERM, sighandler) == SIG_ERR) {
		print_error("signal: errno %d", errno);
		exit(EXIT_FAILURE);
	}

	srand(time(NULL));
	g_my_nonce = ((uint64_t)rand() << 32) | (uint64_t)rand();

	g_epoll_fd = epoll_create(1);
	if (g_epoll_fd == -1) {
		print_error("epoll_create: errno %d", errno);
		exit(EXIT_FAILURE);
	}
}

void print_usage(void)
{
	printf(
	    "usage: mapbtc [--noipv6] [--verbose]\n"
	    "  --noipv6   ignore IPv6 peers\n"
	    "  --verbose  print debug output\n");
}

void parse_args(int argc, char **argv)
{
	while (++argv, --argc) {
		if (strcmp(*argv, "-h") == 0 || strcmp(*argv, "--help") == 0) {
			print_usage();
			exit(EXIT_SUCCESS);
		} else if (strcmp(*argv, "--noipv6") == 0) {
			g_no_ipv6 = true;
		} else if (strcmp(*argv, "--verbose") == 0) {
			g_verbose = true;
		} else {
			print_usage();
			exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char **argv)
{
	parse_args(argc, argv);
	init_program();
	open_output_files();
	get_initial_peers();
	set_max_conn();
	mainloop();
	close_output_files();

	return 0;
}
