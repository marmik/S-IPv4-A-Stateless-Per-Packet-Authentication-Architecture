#include "s_ipv4.h"
#include "crypto_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#if defined(__APPLE__)
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#else
#include <endian.h>
#endif

int opt_replay = 0;
int opt_bad_hmac = 0;
int opt_spoof_node = 0;
int opt_truncated = 0;
int opt_oversize = 0;
int opt_v1_flag = 0;
int opt_flood = 1;
uint64_t opt_force_fill = 0;

int main(int argc, char *argv[]) {
    const char *ip = "127.0.0.1";
    int port = 9999;
    const char *payload_str = "Hello S-IPv4!";
    uint64_t replay_nonce = 0;
    uint64_t replay_ts = 0;

    int pos = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--replay") == 0) {
            opt_replay = 1;
            if (i + 2 < argc) {
                replay_nonce = strtoull(argv[i+1], NULL, 16);
                replay_ts = strtoull(argv[i+2], NULL, 10);
                i += 2;
            }
        } else if (strcmp(argv[i], "--bad-hmac") == 0) opt_bad_hmac = 1;
        else if (strcmp(argv[i], "--spoof-node") == 0) opt_spoof_node = 1;
        else if (strcmp(argv[i], "--truncated") == 0) opt_truncated = 1;
        else if (strcmp(argv[i], "--oversize") == 0) opt_oversize = 1;
        else if (strcmp(argv[i], "--v1-flag") == 0) opt_v1_flag = 1;
        else if (strncmp(argv[i], "--flood=", 8) == 0) opt_flood = atoi(argv[i] + 8);
        else if (strncmp(argv[i], "--force-fill=", 13) == 0) {
#ifdef SIPV4_TEST_MODE
            opt_force_fill = strtoull(argv[i] + 13, NULL, 10);
#endif
        }
        else if (argv[i][0] != '-') {
            if (pos == 0) ip = argv[i];
            else if (pos == 1) port = atoi(argv[i]);
            else if (pos == 2) payload_str = argv[i];
            pos++;
        }
    }

    uint8_t master[S_IPV4_KEY_LEN];
    memset(master, 0x11, S_IPV4_KEY_LEN);
    crypto_init(master);

    epoch_key_entry_t entry;
    // We generated it with epoch 1 in crypto_init
    uint8_t fake_epoch[32];
    sipv4_hkdf_derive_epoch_key(master, 1, fake_epoch);
    uint8_t fake_node[8];
    sipv4_derive_node_id(fake_epoch, fake_node);
    crypto_get_entry(fake_node, &entry);
    
    // Only print startup if not in flood, to avoid spam, or just let it print. The prompt wants it.
    uint64_t n_val = 0;
    memcpy(&n_val, entry.node_id, 8);
    fprintf(stderr, "[S-IPv4 V2] Version 2.0 | NodeID: %016llX | key_ver: %u\n", (unsigned long long)be64toh(n_val), entry.key_ver);

    size_t payload_len = opt_oversize ? 1500 : strlen(payload_str);
    if (opt_force_fill > 0) {
        char special[128];
        snprintf(special, sizeof(special), "FORCE_FILL:%llu", (unsigned long long)opt_force_fill);
        payload_len = strlen(special);
        payload_str = strdup(special);
    }
    
    if (payload_len > S_IPV4_MAX_PAYLOAD) {
        printf("Payload exceeds S_IPV4_MAX_PAYLOAD\n");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

#if defined(__APPLE__)
    int val = 1;
    setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(val));
#else
    int val = IP_PMTUDISC_DO;
    setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
#endif

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = inet_addr(ip);

    for (int count = 0; count < opt_flood; count++) {
        uint8_t buf[S_IPV4_V2_HEADER_SIZE + payload_len];
        s_ipv4_v2_header_t hdr;
        memset(&hdr, 0, sizeof(hdr));

        hdr.s_flag = opt_v1_flag ? S_IPV4_FLAG_V1 : S_IPV4_FLAG_V2;

        if (opt_spoof_node) {
            memset(hdr.node_id, 0xBB, 8);
        } else {
            memcpy(hdr.node_id, entry.node_id, 8);
        }

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        
        static uint64_t nonce_ctr = 0;
        if (nonce_ctr == 0) nonce_ctr = ts.tv_nsec ^ (uint64_t)getpid();
        
        if (opt_replay && replay_nonce != 0) {
            hdr.nonce = replay_nonce;
            hdr.timestamp = replay_ts;
        } else {
            hdr.timestamp = ts.tv_sec;
            hdr.nonce = nonce_ctr++;
            if (opt_replay) hdr.nonce--; // generic replay
        }
        
        hdr.key_ver = entry.key_ver;

        uint8_t payload[S_IPV4_MAX_PAYLOAD];
        memset(payload, 0x42, payload_len);
        if (!opt_oversize) memcpy(payload, payload_str, payload_len);

        crypto_compute_token(entry.current_key, hdr.timestamp, hdr.nonce, payload, payload_len, hdr.hmac);

        if (opt_bad_hmac) hdr.hmac[0] ^= 0xFF;

        printf("Sent packet! Nonce: 0x%016llX Timestamp: %llu\n", (unsigned long long)hdr.nonce, (unsigned long long)hdr.timestamp);

        hdr.timestamp = htobe64(hdr.timestamp);
        hdr.nonce = htobe64(hdr.nonce);
        hdr.key_ver = htons(hdr.key_ver);

        size_t send_len = opt_truncated ? 3 : S_IPV4_V2_HEADER_SIZE + payload_len;

        memcpy(buf, &hdr, S_IPV4_V2_HEADER_SIZE);
        if (!opt_truncated) {
            memcpy(buf + S_IPV4_V2_HEADER_SIZE, payload, payload_len);
        }

        sendto(sock, buf, send_len, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    }
    
    close(sock);
    return 0;
}
