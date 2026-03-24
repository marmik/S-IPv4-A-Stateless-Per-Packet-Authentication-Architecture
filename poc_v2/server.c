#include "s_ipv4.h"
#include "crypto_core.h"
#include "replay_protection.h"
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
#define be64toh(x) OSSwapBigToHostInt64(x)
#else
#include <endian.h>
#endif

tiered_bloom_t tb;

const char *shim_result_str(shim_result_t r) {
    switch(r) {
        case SHIM_ACCEPT: return "ACCEPT_OK";
        case SHIM_DROP_TRUNCATED: return "TRUNCATED";
        case SHIM_DROP_UNKNOWN_NODE: return "INVALID_TOKEN"; // spoof node
        case SHIM_DROP_INVALID_TOKEN: return "INVALID_TOKEN";
        case SHIM_DROP_EXPIRED: return "EXPIRED_TIMESTAMP"; // test 3
        case SHIM_DROP_REPLAY: return "REPLAY_DETECTED"; // test 2
        case SHIM_DROP_BAD_VERSION: return "BAD_VERSION";
        case SHIM_DROP_RATE_LIMITED: return "RATE_LIMITED";
        case SHIM_DEGRADED_MODE: return "DEGRADED_MODE";
        case SHIM_ACCEPT_AUDIT: return "ACCEPT_AUDIT";
        default: return "UNKNOWN";
    }
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    int audit_mode = 0;
    int port = 9999;
    
    if (argc > 1) port = atoi(argv[1]);
    for (int i=1; i<argc; i++) {
        if (strcmp(argv[i], "AUDIT") == 0) audit_mode = 1;
        if (strcmp(argv[i], "--audit") == 0) audit_mode = 1;
    }

    uint8_t master[S_IPV4_KEY_LEN];
    memset(master, 0x11, S_IPV4_KEY_LEN);
    crypto_init(master);

    if (tiered_bloom_init(&tb) < 0) {
        perror("tiered_bloom_init");
        return 1;
    }

    printf("[S-IPv4 V2] Server started | port: %d | mode: %s | tiered Bloom: active\n", port, audit_mode ? "AUDIT" : "ENFORCE");

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        return 1;
    }

    for (;;) {
        uint8_t buf[2048];
        struct sockaddr_in cliaddr;
        socklen_t len = sizeof(cliaddr);
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&cliaddr, &len);
        if (n < 0) continue;

        if (n < S_IPV4_V2_HEADER_SIZE) {
            shim_result_t res = SHIM_DROP_TRUNCATED;
            if (audit_mode) printf("AUDIT_FAIL: %s\n", shim_result_str(res));
            else printf("DROP: %s\n", shim_result_str(res));
            continue;
        }

        s_ipv4_v2_header_t *hdr = (s_ipv4_v2_header_t *)buf;

        if (hdr->s_flag != S_IPV4_FLAG_V2) {
            shim_result_t res = SHIM_DROP_BAD_VERSION;
            if (audit_mode) printf("AUDIT_FAIL: %s\n", shim_result_str(res));
            else printf("DROP: %s\n", shim_result_str(res));
            continue;
        }

        epoch_key_entry_t entry;
        if (!crypto_get_entry(hdr->node_id, &entry)) {
            shim_result_t res = SHIM_DROP_UNKNOWN_NODE;
            if (audit_mode) {
                printf("AUDIT_FAIL: %s\n", shim_result_str(res));
                printf("Audit payload: %.*s\n", (int)(n - S_IPV4_V2_HEADER_SIZE), buf + S_IPV4_V2_HEADER_SIZE);
            } else {
                printf("DROP: %s\n", shim_result_str(res));
            }
            continue;
        }

        uint64_t ts = be64toh(hdr->timestamp);
        uint64_t nonce = be64toh(hdr->nonce);
        uint16_t kv = ntohs(hdr->key_ver);

        struct timespec t_now;
        clock_gettime(CLOCK_MONOTONIC, &t_now);
        uint64_t mono_now = t_now.tv_sec;
        double fill = tiered_bloom_fill_pct(&tb);
        uint32_t aw = sipv4_adaptive_window_sec(fill);
        uint64_t diff = mono_now > ts ? (mono_now - ts) : (ts - mono_now);
        
        int replay_res = 0;
        if ((aw == 0 && diff > 0) || (aw > 0 && diff > aw)) {
            replay_res = 1; // EXPIRED
        } else if (tiered_bloom_check(&tb, nonce)) {
            replay_res = 2; // REPLAY
        }

        if (replay_res != 0) {
            shim_result_t res = (replay_res == 1) ? SHIM_DROP_EXPIRED : SHIM_DROP_REPLAY;
            if (audit_mode) printf("AUDIT_FAIL: %s\n", shim_result_str(res));
            else printf("DROP: %s\n", shim_result_str(res));
            continue;
        }

        size_t payload_len = n - S_IPV4_V2_HEADER_SIZE;
        uint8_t *payload = buf + S_IPV4_V2_HEADER_SIZE;

        shim_result_t res = crypto_verify_token(&entry, ts, nonce, payload, payload_len, hdr->hmac);
        if (res != SHIM_ACCEPT) {
            if (audit_mode) {
                printf("AUDIT_FAIL: %s\n", shim_result_str(res));
                printf("Audit payload: %.*s\n", (int)payload_len, payload);
            } else {
                printf("DROP: %s\n", shim_result_str(res));
            }
            continue;
        }
        
#ifdef SIPV4_TEST_MODE
        if (payload_len >= 11 && memcmp(payload, "FORCE_FILL:", 11) == 0) {
            uint64_t f_count = strtoull((const char *)payload + 11, NULL, 10);
            tiered_bloom_force_fill(&tb, f_count);
        }
#endif

        tiered_bloom_insert(&tb, nonce);
        printf("%s: key_ver:%u\n", shim_result_str(SHIM_ACCEPT), kv);
    }
    
    return 0;
}
