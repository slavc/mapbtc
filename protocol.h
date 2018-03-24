#ifndef MAPBTC_PROTOCOL_H
#define MAPBTC_PROTOCOL_H

#include <stdlib.h>
#include <stdint.h>

#define NELEMS(a) (sizeof(a)/sizeof(*(a)))

#define USER_AGENT "/mapbtc:0.0.1/"

#define MAINNET_PORT 8333
#define NODE_NETWORK 1
#define MAX_MSG_SIZE (32*1024*1024)
#define PROTOCOL_VERSION 70015

struct hdr {
	uint32_t magic;
	char cmd[12];
	uint32_t payload_size;
	uint32_t cksum;
};
#define HDR_MAGIC_SIZE 4
#define HDR_CMD_SIZE 12
#define HDR_PAYLOAD_SIZE_SIZE 4
#define HDR_CKSUM_SIZE 4
#define HDR_MAGIC_OFF 0
#define HDR_CMD_OFF 4
#define HDR_PAYLOAD_SIZE_OFF (4+12)
#define HDR_CKSUM_OFF (4+12+4)
#define HDR_SIZE (HDR_MAGIC_SIZE + HDR_CMD_SIZE + HDR_PAYLOAD_SIZE_SIZE + HDR_CKSUM_SIZE)
bool parse_hdr(uint8_t *buf, size_t buf_size, struct hdr *hdr);
inline bool is_version_msg(const struct hdr *hdr)
{
	return memcmp(hdr->cmd, "version\0\0\0\0\0", HDR_CMD_SIZE) == 0;
}
inline bool is_addr_msg(const struct hdr *hdr)
{
	return memcmp(hdr->cmd, "addr\0\0\0\0\0\0\0\0", HDR_CMD_SIZE) == 0;
}

#define ADDR_IP_SIZE 16
#define ADDR_IP_OFF (4+8)
#define ADDR_REC_SIZE (4+8+16+2) // size of one record in addr message

struct version {
	uint32_t protocol;
	uint64_t services;
	char user_agent[128];
	uint32_t start_height;
};
#define VERSION_PROTOCOL_SIZE 4
#define VERSION_SERVICES_SIZE 8
#define VERSION_SERVICES_OFF 4
#define VERSION_TIMESTAMP_SIZE 8
#define VERSION_RECV_SERVICE_SIZE 8
#define VERSION_RECV_IP_SIZE 16
#define VERSION_RECV_PORT_SIZE 2
#define VERSION_TRANS_SERVICE_SIZE 8
#define VERSION_TRANS_IP_SIZE 16
#define VERSION_TRANS_PORT 2
#define VERSION_NONCE_SIZE 8
#define VERSION_START_HEIGHT 4
#define VERSION_RELAY_SIZE 1
#define VERSION_UA_LEN_OFF (4+8+8+8+16+2+8+16+2+8)
#define VERSION_MIN_PAYLOAD_SIZE (4+8+8+8+16+2+8+16+2+8+4+1 + 2)
bool parse_version_msg(uint8_t *buf, size_t buf_size, struct version *ver);

uint32_t msg_cksum(const uint8_t *buf, size_t size);

size_t pack_header(uint8_t *buf, size_t buf_size, const char *cmd);
size_t pack_version_msg(uint8_t *buf, size_t buf_size, const uint64_t *nonce);
size_t pack_payloadless_msg(uint8_t *buf, size_t buf_size, const char *cmd);
size_t pack_verack_msg(uint8_t *buf, size_t buf_size);
size_t pack_getaddr_msg(uint8_t *buf, size_t buf_size);

#endif
