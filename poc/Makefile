# ─────────────────────────────────────────────────────────────────
# Makefile for S-IPv4 Proof of Concept
# Portable across Apple Silicon and Intel Macs via brew --prefix.
# ─────────────────────────────────────────────────────────────────

CC       := cc
OPENSSL  := $(shell brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)

CFLAGS   := -Wall -Wextra -Wpedantic -std=c11 -O2 \
            -I$(OPENSSL)/include
LDFLAGS  := -L$(OPENSSL)/lib -lssl -lcrypto

# Source files shared by both client and server
COMMON_SRC := crypto_core.c replay_protection.c s_ipv4_shim.c

.PHONY: all clean

all: client server
	@echo "✅  Build complete.  Run ./test_run.sh to verify."

client: client.c $(COMMON_SRC) s_ipv4.h s_ipv4_shim.h crypto_core.h replay_protection.h
	$(CC) $(CFLAGS) -o $@ client.c $(COMMON_SRC) $(LDFLAGS)

server: server.c $(COMMON_SRC) s_ipv4.h s_ipv4_shim.h crypto_core.h replay_protection.h
	$(CC) $(CFLAGS) -o $@ server.c $(COMMON_SRC) $(LDFLAGS)

clean:
	rm -f client server
