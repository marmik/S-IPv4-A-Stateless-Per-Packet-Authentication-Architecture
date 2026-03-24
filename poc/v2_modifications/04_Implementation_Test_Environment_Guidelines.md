# S-IPv4 Implementation & Test Environment Guidelines
**Document Type:** Test Engineering Reference
**Scope:** V1 Loopback Validation → VLAN Network Segment Deployment → V2 Network Test Workflow
**Purpose:** Define a reproducible, journal-documentable test workflow for both V1 and V2

---

## OVERVIEW — TEST WORKFLOW PHILOSOPHY

The testing methodology follows a staged progression designed to isolate variables at each phase and produce publishable data at every stage:

```
PHASE 1: V1 Loopback (Complete)
    → Single machine, macOS loopback, controlled environment
    → Validates: cryptographic correctness, basic throughput, Bloom filter accuracy

PHASE 2: V1 VLAN Network Segment (This Document)
    → Two or more physical/virtual hosts on an isolated VLAN
    → Validates: real NIC behavior, cross-machine clock drift, actual wire-rate performance,
                 real network jitter, fragmentation behavior

PHASE 3: V2 Implementation
    → Apply all V2 upgrades informed by Phase 1 and Phase 2 findings
    → Validates: V2 improvements over V1 on same test infrastructure

PHASE 4: V2 VLAN Network Segment Re-test
    → Repeat Phase 2 test suite on V2
    → Produces: final comparative dataset for journal publication
```

This four-phase structure ensures every paper claim is backed by progressively rigorous evidence and creates a natural narrative arc for a journal paper: "We validated V1 on loopback, found these limitations in real network conditions, designed V2 to address them, and validated V2 under identical conditions."

---

## PHASE 2 — V1 VLAN NETWORK SEGMENT SETUP

### 2.1 — Hardware Requirements

#### Minimum Configuration (Two-Host Setup)
```
HOST A — Sender
    CPU:    Any modern x86-64 or ARM (matching the V1 implementation platform)
    RAM:    4 GB minimum
    NIC:    1GbE minimum — Intel I210/I350 recommended (good Linux driver support)
    OS:     Ubuntu 22.04 LTS (for Linux baseline data; complements macOS V1 results)
    Role:   S-IPv4 packet sender, benchmark driver

HOST B — Receiver
    CPU:    Same or similar to Host A (document differences explicitly)
    RAM:    4 GB minimum
    NIC:    1GbE minimum — same NIC family as Host A preferred
    OS:     Ubuntu 22.04 LTS
    Role:   S-IPv4 packet receiver, performance measurement

NETWORK DEVICE (one of):
    Option A: Single managed switch with VLAN support (Cisco Catalyst 2960, Netgear M4250, etc.)
    Option B: Single router with L3 VLAN routing if inter-VLAN testing is desired
    Option C: Two separate routers connected by a trunk link (for multi-hop testing)
```

#### Preferred Configuration (Three-Host Setup — Adds Attacker Node)
```
HOST C — Adversary/Stress Node
    Purpose: Generates adversarial traffic (replay floods, Bloom filter saturation attacks,
             invalid HMAC floods, random node_id floods)
    OS:      Ubuntu 22.04 LTS
    NIC:     Same VLAN as Host A and B
```

---

### 2.2 — VLAN DESIGN

#### Option A — Single Switch, Single Router (Recommended for V1 Testing)

```
NETWORK TOPOLOGY:

    [Host A — Sender]         [Host B — Receiver]      [Host C — Adversary]
          |                         |                          |
          | Access port             | Access port              | Access port
          | VLAN 100                | VLAN 100                 | VLAN 100
          |                         |                          |
    +===================== MANAGED SWITCH =======================+
    |                     Trunk port                            |
    |              (carries VLAN 100 + VLAN 1 mgmt)             |
    +============================================================+
                                |
                         [Router / L3 Switch]
                         Management access
                         VLAN 100: 192.168.100.0/24
```

**IP Assignment:**
```
Host A (Sender):    192.168.100.10/24
Host B (Receiver):  192.168.100.20/24
Host C (Adversary): 192.168.100.30/24
Gateway:            192.168.100.1/24
```

#### Option B — Two Routers, Trunk Link (Adds Routing Hop for Multi-Hop Testing)

```
    [Host A — Sender]                           [Host B — Receiver]
          |                                           |
    Access port VLAN 100                       Access port VLAN 200
          |                                           |
    [ROUTER 1]  ====== Trunk Link (VLAN 100+200) ==== [ROUTER 2]
    Gi0/0: 192.168.100.1/24                    Gi0/0: 192.168.200.1/24
    Gi0/1: 10.0.0.1/30 (trunk)               Gi0/1: 10.0.0.2/30 (trunk)
```

**Use case for Option B:** Tests S-IPv4 across a routed hop, confirming that source IP changes at the router (NAT if configured, or simple routing) do not break HMAC validation. This directly validates the NAT-independence claim in a real multi-hop environment.

---

### 2.3 — SWITCH CONFIGURATION (Cisco IOS Example)

```cisco
! ============================================
! VLAN CREATION
! ============================================
vlan 100
 name SIPV4_TEST_SEGMENT

! ============================================
! ACCESS PORTS (one per host)
! ============================================
interface GigabitEthernet0/1
 description HOST_A_SENDER
 switchport mode access
 switchport access vlan 100
 spanning-tree portfast
 no shutdown

interface GigabitEthernet0/2
 description HOST_B_RECEIVER
 switchport mode access
 switchport access vlan 100
 spanning-tree portfast
 no shutdown

interface GigabitEthernet0/3
 description HOST_C_ADVERSARY
 switchport mode access
 switchport access vlan 100
 spanning-tree portfast
 no shutdown

! ============================================
! TRUNK PORT (to router for management access)
! ============================================
interface GigabitEthernet0/24
 description TRUNK_TO_ROUTER
 switchport mode trunk
 switchport trunk allowed vlan 1,100
 no shutdown

! ============================================
! OPTIONAL: VLAN RATE LIMITING (for flood tests)
! Controls inbound storm from Host C
! ============================================
interface GigabitEthernet0/3
 storm-control broadcast level 10.00
 storm-control action shutdown
```

---

### 2.4 — ROUTER CONFIGURATION (Cisco IOS, Option B Two-Router Setup)

```cisco
! ============================================
! ROUTER 1 (Sender-side)
! ============================================
interface GigabitEthernet0/0
 description TO_HOST_A_VLAN100
 ip address 192.168.100.1 255.255.255.0
 no shutdown

interface GigabitEthernet0/1
 description TRUNK_TO_ROUTER2
 ip address 10.0.0.1 255.255.255.252
 no shutdown

ip route 192.168.200.0 255.255.255.0 10.0.0.2

! ============================================
! ROUTER 2 (Receiver-side)
! ============================================
interface GigabitEthernet0/0
 description TO_HOST_B_VLAN200
 ip address 192.168.200.1 255.255.255.0
 no shutdown

interface GigabitEthernet0/1
 description TRUNK_TO_ROUTER1
 ip address 10.0.0.2 255.255.255.252
 no shutdown

ip route 192.168.100.0 255.255.255.0 10.0.0.1
```

**Note on NAT Testing:** To test NAT independence, add the following to Router 1:
```cisco
! NAT configuration on Router 1 — translates Host A's source IP
interface GigabitEthernet0/1
 ip nat outside
interface GigabitEthernet0/0
 ip nat inside
ip nat inside source list 1 interface GigabitEthernet0/1 overload
access-list 1 permit 192.168.100.0 0.0.0.255
```
With NAT enabled, Host B receives packets with source IP 10.0.0.1 (Router 1's WAN IP) instead of 192.168.100.10. S-IPv4 HMAC validation should still pass, confirming NAT independence.

---

### 2.5 — HOST SETUP (Ubuntu 22.04)

```bash
# ============================================
# HOST A and HOST B — Common Setup
# ============================================

# Install build dependencies
sudo apt update && sudo apt install -y \
    build-essential \
    libssl-dev \
    libbpf-dev \
    iproute2 \
    ntp \
    chrony \
    iperf3 \
    tcpdump \
    ethtool \
    cpupower-utils \
    linux-tools-$(uname -r)  # perf

# Disable NIC offloads for accurate per-packet measurement
# (offloads can cause batching that distorts latency measurements)
sudo ethtool -K eth0 gso off gro off tso off rx off tx off

# Set CPU to performance governor (eliminates CPU frequency scaling noise)
sudo cpupower frequency-set -g performance

# Increase socket buffer sizes for high-throughput testing
echo 'net.core.rmem_max=26214400' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max=26214400' | sudo tee -a /etc/sysctl.conf
echo 'net.core.netdev_max_backlog=10000' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Time synchronization — critical for timestamp window testing
sudo apt install -y chrony
sudo systemctl enable chrony
# Verify sync quality (want offset < 10ms for 5-second window)
chronyc tracking
```

---

### 2.6 — NTP / CLOCK SYNCHRONIZATION SETUP

Clock synchronization is critical for S-IPv4's timestamp validation. Both hosts must use the same NTP server or be directly synchronized.

```bash
# Option A — Use same external NTP server (both hosts)
sudo tee /etc/chrony/chrony.conf << 'EOF'
server pool.ntp.org iburst
makestep 1.0 3
rtcsync
EOF
sudo systemctl restart chrony

# Option B — Host A acts as NTP server for Host B (isolated lab without internet)
# On Host A:
sudo tee /etc/chrony/chrony.conf << 'EOF'
local stratum 8
allow 192.168.100.0/24
EOF

# On Host B:
sudo tee /etc/chrony/chrony.conf << 'EOF'
server 192.168.100.10 iburst
EOF
sudo systemctl restart chrony

# Verify synchronization on both hosts
chronyc sources -v
chronyc tracking
# Target: offset < 10ms (well within 5-second window)
# Document: actual measured offset for paper
```

---

## PHASE 2 — TEST SUITE DEFINITION

### 2.7 — Test Suite Structure

#### TEST GROUP 1 — Baseline Performance (Replicate V1 Results on Real Hardware)

```
TEST 1.1 — Raw UDP Throughput Baseline
    sender: iperf3 -u -c 192.168.100.20 -b 0 -l 128 -t 30
    receiver: iperf3 -s -u
    record: pps, bandwidth, jitter, loss
    purpose: Establishes real-network UDP baseline for comparison with loopback V1

TEST 1.2 — S-IPv4 Throughput (matching V1 conditions)
    sender: S-IPv4 sender at 10k, 100k, 1M packets (128-byte payload)
    receiver: S-IPv4 receiver with full verification
    record: pps, overhead vs TEST 1.1
    purpose: Direct replication of V1 Table II on real hardware

TEST 1.3 — Cryptographic Latency (matching V1 CDF measurement)
    method: Same 100,000 sample methodology, clock_gettime(CLOCK_MONOTONIC)
    record: CDF with P50/P95/P99, compare with V1 Table I
    note: Linux CLOCK_MONOTONIC has ~20ns resolution vs macOS 1µs — expect better P50 data
```

#### TEST GROUP 2 — Real Network Differential Tests (New in V1 Network Phase)

```
TEST 2.1 — Cross-Machine Timestamp Window Validation
    purpose: Verify that NTP offset does not cause false timestamp rejections
    method:  Degrade NTP sync to known offsets (0ms, 100ms, 500ms, 1000ms, 2000ms)
             Send valid packets and measure rejection rate at each offset level
    record:  Rejection rate vs NTP offset
    expected: No rejections below 2000ms offset (well inside 5-second window)
    publish: Validates timestamp window selection for the paper

TEST 2.2 — NIC Interrupt Coalescing Impact on Latency
    purpose: Measure per-packet latency distribution with real NIC vs loopback
    method:  Run TEST 1.3 with ethtool coalescing enabled (default) and disabled
    record:  CDF comparison — expect higher P99 with coalescing enabled
    publish: Honest latency characterization for journal

TEST 2.3 — Cross-Router NAT Independence Validation (Option B topology)
    purpose: Confirm HMAC validation succeeds after NAT source IP translation
    method:  Enable NAT on Router 1, send 100,000 S-IPv4 packets
    record:  Verification success rate (expect 100%)
    publish: Empirical confirmation of NAT independence claim

TEST 2.4 — Path MTU Fragmentation Behavior
    purpose: Characterize behavior when packet exceeds MTU (V1 known issue)
    method:  Send S-IPv4 packets with payload > 1473 bytes WITHOUT IP_DONTFRAG
             Observe reassembly state on receiver
    record:  Successful verifications, failed verifications, state buffer size
    publish: Quantifies fragmentation problem for V2 motivation
```

#### TEST GROUP 3 — Stress Testing and Adversarial Scenarios

```
TEST 3.1 — Sustained Load Stress Test
    duration: 10 minutes at maximum pps
    record: Throughput over time, CPU utilization, memory growth
    purpose: Identify any memory leaks, CPU drift, or throughput degradation under sustained load

TEST 3.2 — Bloom Filter Saturation Attack (Host C)
    method:  Host C floods Host B with valid-timestamp, valid-HMAC (using valid Epoch Key),
             unique-nonce packets at maximum rate for 60 seconds
    record:  Bloom filter fill % over time, FP rate increase, impact on legitimate Host A traffic
    purpose: Empirically characterize the V1 "saturation cliff" for V2 motivation paper section

TEST 3.3 — Invalid HMAC Flood (Host C)
    method:  Host C floods valid node_id but garbage HMAC at 100k pps for 60 seconds
    record:  Host B CPU utilization, legitimate traffic impact, early-exit effectiveness
    purpose: Validates early-exit pipeline performance under flood

TEST 3.4 — Random node_id Flood (Host C)
    method:  Host C floods with random 8-byte node_ids at 100k pps
    record:  Host B CPU utilization, node_id lookup rejection rate, drop latency
    purpose: Validates early-exit performance at node_id lookup step

TEST 3.5 — Replay Attack Simulation (Host C)
    method:  Host C captures 1000 valid S-IPv4 packets and replays them
             immediately (within 1 second), after 3 seconds, after 10 seconds
    record:  Rejection rate at each interval
    expected: 100% rejection in all cases (Bloom filter for <5s, timestamp for >5s)
    publish: Empirical replay resistance data for journal

TEST 3.6 — Mixed Legitimate + Adversarial Traffic
    method:  Host A sends legitimate traffic at 50k pps while Host C floods at 100k pps
    record:  Host A packet delivery rate, latency impact, throughput degradation
    purpose: Characterizes collateral damage from flood on legitimate traffic
```

---

### 2.8 — MEASUREMENT INSTRUMENTATION

```bash
# On Host B (receiver) — capture detailed packet timing
sudo tcpdump -i eth0 -w /tmp/sipv4_capture.pcap udp port [S-IPv4 port] &

# CPU monitoring during tests
mpstat -P ALL 1 > /tmp/cpu_stats.log &

# Memory monitoring
vmstat 1 > /tmp/mem_stats.log &

# NIC statistics
ethtool -S eth0 > /tmp/nic_stats_before.txt
# [run test]
ethtool -S eth0 > /tmp/nic_stats_after.txt

# Network queue depth (shows if kernel buffer is overflowing)
watch -n 1 'ss -s'

# After test: analyze pcap for inter-packet timing
tshark -r /tmp/sipv4_capture.pcap -T fields \
    -e frame.time_relative \
    -e ip.src \
    -e udp.length \
    > /tmp/timing_analysis.csv
```

---

## PHASE 3 — V2 IMPLEMENTATION SEQUENCE

After Phase 2 data is collected and analyzed, implement V2 changes in the following order:

```
STEP 1 — IP_DONTFRAG enforcement (quick win, fixes fragmentation)
STEP 2 — Adaptive Bloom filter (window tightening + rotation speed)
STEP 3 — Protocol version field (0x94 → versioned)
STEP 4 — key_ver field addition to header (43-byte header)
STEP 5 — key-derived node_id
STEP 6 — Epoch Key lifecycle definition (rotation + overlap window)
STEP 7 — Tiered three-level Bloom filter (P1 priority)
STEP 8 — Compact header mode (P1)
STEP 9 — Rejection signal packet (P2)
STEP 10 — Monotonic clock anchoring (P2)
```

Each step should be:
1. Implemented on a feature branch
2. Tested on loopback to confirm no regression
3. Merged only after loopback tests pass
4. Documented in the changelog with the V1 problem it addresses

---

## PHASE 4 — V2 VLAN RE-TEST

Repeat the complete Phase 2 test suite (all TEST groups 1–3) on V2 implementation using **identical infrastructure**.

### Key Comparison Points for Paper

| Metric | V1 Loopback | V1 Network | V2 Network | Delta V1→V2 |
|---|---|---|---|---|
| Token generation latency (P99) | 1.0 µs | TBD | TBD | TBD |
| Throughput overhead at 1M pps | 18.4% | TBD | TBD | TBD |
| Bloom filter FP at 1M nonces | 0.000467% | TBD | TBD | TBD |
| Bloom filter saturation recovery time | N/A (not tested) | TBD | TBD | TBD |
| NAT traversal success rate | N/A (single machine) | TBD | TBD | TBD |
| Timestamp rejection rate at 2s NTP offset | N/A | TBD | TBD | TBD |

This table, filled with real data, becomes the core of the V2 evaluation section in the journal paper.

---

## DOCUMENTATION STANDARDS FOR JOURNAL SUBMISSION

Every test run must record:

```
TEST RUN METADATA (required for each test)
    date_time:          ISO 8601 timestamp
    hardware_host_a:    CPU model, RAM, NIC model, driver version
    hardware_host_b:    CPU model, RAM, NIC model, driver version
    switch_model:       Model and firmware version
    router_model:       Model and IOS version (if applicable)
    os_version:         uname -a output
    openssl_version:    openssl version
    ntp_offset_ha:      chronyc tracking output (RMS offset)
    ntp_offset_hb:      chronyc tracking output (RMS offset)
    s_ipv4_git_hash:    git rev-parse HEAD
    test_id:            TEST_X.Y as defined in this document
    raw_data_path:      /path/to/csv or pcap
```

This metadata record ensures the test environment is fully reproducible and documents the exact conditions under which results were obtained — a requirement for IEEE journal reproducibility standards.

---

## APPENDIX — TROUBLESHOOTING COMMON SETUP ISSUES

| Issue | Symptom | Resolution |
|---|---|---|
| High false rejection rate | Valid packets rejected at receiver | Check NTP offset — run `chronyc tracking` on both hosts |
| Zero throughput on VLAN | No packets arriving at Host B | Verify switch port VLAN assignment — `show vlan brief` on switch |
| Fragmentation occurring | tcpdump shows IP fragments | Confirm IP_DONTFRAG is set on sender socket; verify path MTU with `tracepath` |
| CPU throttling distorting results | Throughput drops after initial burst | Confirm CPU governor is set to `performance` — `cpupower frequency-info` |
| NIC coalescing batching distorting latency | P99 latency very high, P50 = 0 | Disable coalescing: `ethtool -C eth0 rx-usecs 0 tx-usecs 0` |
| Bloom filter FP rate higher than V1 | Real network has higher FP | Expected — real network has more out-of-order delivery; document and explain in paper |
| S-IPv4 build fails on Linux | Compilation error | Port macOS-specific socket options to Linux equivalents; `IP_DONTFRAG` → `IP_MTU_DISCOVER` |

---

*This document defines the test engineering standard for S-IPv4 V1 and V2 validation. All test results obtained following these procedures should be cited with reference to this guideline document in the journal submission.*
