#include "s_ipv4.h"
#include "s_ipv4_shim.h"
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

        /* ── Dispatch by first byte (version flag) ──────────────── */
        uint8_t flag = buf[0];

        if (flag == S_IPV4_FLAG_COMPACT) {
            /* ── Compact mode (0x96, 21-byte header) ──────────── */
            if (n < S_IPV4_COMPACT_HEADER_SIZE) {
                printf("DROP: %s\n", shim_result_str(SHIM_DROP_TRUNCATED));
                continue;
            }
            s_ipv4_compact_header_t *chdr = (s_ipv4_compact_header_t *)buf;

            epoch_key_entry_t entry;
            if (!crypto_get_entry_compact(chdr->node_id, &entry)) {
                if (audit_mode) {
                    printf("AUDIT_FAIL: %s\n", shim_result_str(SHIM_DROP_UNKNOWN_NODE));
                    printf("Audit payload: %.*s\n", (int)(n - S_IPV4_COMPACT_HEADER_SIZE),
                           buf + S_IPV4_COMPACT_HEADER_SIZE);
                } else {
                    printf("DROP: %s\n", shim_result_str(SHIM_DROP_UNKNOWN_NODE));
                }
                continue;
            }

            uint32_t nonce = ntohl(chdr->nonce);
            size_t payload_len = n - S_IPV4_COMPACT_HEADER_SIZE;
            uint8_t *payload = buf + S_IPV4_COMPACT_HEADER_SIZE;

            shim_result_t res = crypto_verify_token_compact(&entry, nonce,
                                                             payload, payload_len,
                                                             chdr->hmac);
            if (res != SHIM_ACCEPT) {
                if (audit_mode) {
                    printf("AUDIT_FAIL: %s\n", shim_result_str(res));
                    printf("Audit payload: %.*s\n", (int)payload_len, payload);
                } else {
                    printf("DROP: %s\n", shim_result_str(res));
                }
                continue;
            }

            if (tiered_bloom_check(&tb, (uint64_t)nonce)) {
                printf("DROP: %s\n", shim_result_str(SHIM_DROP_REPLAY));
                continue;
            }
            tiered_bloom_insert(&tb, (uint64_t)nonce);
            printf("[COMPACT] %s: nonce:0x%08X\n", shim_result_str(SHIM_ACCEPT), nonce);

        } else if (flag == S_IPV4_FLAG_V2) {
            /* ── Full V2 mode (0x95, 43-byte header) ─────────── */
            if (n < S_IPV4_V2_HEADER_SIZE) {
                shim_result_t res = SHIM_DROP_TRUNCATED;
                if (audit_mode) printf("AUDIT_FAIL: %s\n", shim_result_str(res));
                else printf("DROP: %s\n", shim_result_str(res));
                continue;
            }

            s_ipv4_v2_header_t *hdr = (s_ipv4_v2_header_t *)buf;

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
                replay_res = 1;
            } else if (tiered_bloom_check(&tb, nonce)) {
                replay_res = 2;
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

        } else {
            /* ── Unknown version flag ────────────────────────── */
            if (audit_mode) printf("AUDIT_FAIL: %s\n", shim_result_str(SHIM_DROP_BAD_VERSION));
            else printf("DROP: %s\n", shim_result_str(SHIM_DROP_BAD_VERSION));
        }
    }
    
    return 0;
}
