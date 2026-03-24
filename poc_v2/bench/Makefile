# ─────────────────────────────────────────────────────────────────
# Makefile for S-IPv4 Benchmark Suite
# ─────────────────────────────────────────────────────────────────

CC       := cc
OPENSSL  := $(shell brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)

CFLAGS   := -Wall -Wextra -std=c11 -O2 \
            -I$(OPENSSL)/include -I.. \
            -DS_IPV4_VERSION=\"2.0\" -DS_IPV4_BUILD=\"20260324\" -DSIPV4_TEST_MODE
LDFLAGS  := -L$(OPENSSL)/lib -lssl -lcrypto -lm

# Parent PoC source files (relative to bench/)
POC_SRC  := ../crypto_core.c ../replay_protection.c ../s_ipv4_shim.c

.PHONY: all clean

all: bench_crypto bench_verify bench_throughput bench_memory bench_adversarial bench_profile
	@echo "✅  Benchmark build complete.  Run ./run_all_benchmarks.sh"

bench_crypto: bench_crypto.c $(POC_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(POC_SRC) $(LDFLAGS)

bench_verify: bench_verify.c $(POC_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(POC_SRC) $(LDFLAGS)

bench_throughput: bench_throughput.c $(POC_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(POC_SRC) $(LDFLAGS)

bench_memory: bench_memory.c $(POC_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(POC_SRC) $(LDFLAGS)

bench_adversarial: bench_adversarial.c $(POC_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(POC_SRC) $(LDFLAGS)

bench_profile: bench_profile.c $(POC_SRC)
	$(CC) $(CFLAGS) -DSIPV4_PROFILE -o $@ $< $(POC_SRC) $(LDFLAGS)

clean:
	rm -f bench_crypto bench_verify bench_throughput bench_memory bench_adversarial bench_profile
	rm -f *.csv results.txt *.pdf
