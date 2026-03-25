# RustGuard

A clean-room WireGuard implementation in Rust — userspace and kernel module. No libwg. Cross-platform userspace, Linux kernel module targeting 6.10+.

**8,500+ lines of Rust · 80 tests · 7 crates · userspace + kernel module**

Built as an experiment to understand WireGuard internals by implementing the full protocol from scratch, pushing userspace performance to its limits, then going in-kernel to eliminate the TUN bottleneck entirely.

## Architecture

```
rustguard-crypto/     X25519, ChaCha20-Poly1305, HMAC-BLAKE2s, HKDF, TAI64N (dual std/no_std)
rustguard-core/       Noise_IK handshake, transport sessions, replay window, timers (dual std/no_std)
rustguard-tun/        macOS utun, Linux TUN, multi-queue TUN, AF_XDP, io_uring, BPF loader
rustguard-daemon/     Standard wg.conf tunnel mode (rustguard up)
rustguard-enroll/     Zero-config enrollment, IP pool, Zigbee-style pairing, persistence
rustguard-cli/        CLI: up, serve, join, open, close, status, genkey, pubkey
rustguard-kmod/       Linux kernel module (Rust + C shim, out-of-tree, targets 6.10+)
```

## The Experiment — Commit by Commit

### Phase 1: Protocol Implementation

**Commit 1 — Working tunnel in pure Rust**

Started with the WireGuard whitepaper and built up from cryptographic primitives. X25519 key exchange, ChaCha20-Poly1305 AEAD, BLAKE2s hashing with HKDF key derivation, TAI64N timestamps. Implemented the Noise_IKpsk2 handshake (initiation → response → transport), wire format serialization, and a macOS utun TUN device via raw kernel control sockets. Wired it all into a tunnel loop: TUN reads plaintext → encrypt → UDP send, UDP recv → decrypt → TUN write.

*First test: two peers on localhost, ICMP ping through utun interfaces. 1.2ms RTT. It worked.*

**Commit 2 — Replay protection, timers, Linux TUN**

Added the 2048-bit sliding window anti-replay bitmap. Built the timer state machine (rekey after 120s or 2^60 messages, keepalive, handshake retry with jitter, session expiry). Ported TUN to Linux (`/dev/net/tun` with `IFF_TUN | IFF_NO_PI`). Added signal handling for clean shutdown with route cleanup. Replaced the nanosecond clock hack for sender indices with a proper CSPRNG.

*Tested on two Debian 12 VMs on a bridged network. 0% packet loss, <1ms RTT.*

**Commit 3 — Cookie mechanism, PSK support, XChaCha20**

Implemented WireGuard's DoS protection: `CookieChecker` (server side, rotating secrets) and `CookieState` (client side). XChaCha20-Poly1305 for cookie encryption. MAC1 always present, MAC2 required under load. Added pre-shared key support with backward-compatible wrappers. Cookie Reply message (type 3) with full wire format.

**Commit 4 — IPv6 dual-stack**

Extended the tunnel to handle both IPv4 and IPv6 packets based on IP version byte inspection. Dual-stack TUN configuration on both macOS (`ifconfig inet6`) and Linux (`ip -6 addr add`). AllowedIPs parser handles both v4 and v6 CIDR ranges. Route table updated for both families.

*Dual-stack ping (v4 + v6) between Debian VMs, 0% packet loss.*

### Phase 2: Security Audit

**Commit 5 — Critical and high fixes (OWASP-style audit)**

Went through the codebase with an adversarial mindset:

- **HMAC-BLAKE2s was wrong.** Was using keyed BLAKE2s directly instead of RFC 2104 HMAC (ipad/opad double-hash). KDF output was incorrect and non-interoperable. Fixed.
- **MAC1 checked too late.** DH operations happened before MAC1 verification — an attacker could burn CPU with unauthenticated packets. Moved MAC1 check first.
- **Timestamp replay not enforced.** Stale handshake initiations were accepted, enabling session hijack via captured packets. Fixed.
- **Replay window poisoning.** Window updated before AEAD verification — garbage counters could advance the window. Split into `check()` / `update()`.
- **FD leaks** on TUN creation error paths (both platforms).
- **Linux ifreq padding** was 12 bytes instead of 20 — reading stack garbage for MTU.
- **Peer lookup operator precedence bug** for handshake responses.
- `constant_time_eq` used `black_box` to prevent LLVM from optimizing out the comparison.

**Commit 6 — Medium fixes**

Replaced hand-rolled constant-time comparisons with `subtle::ConstantTimeEq`. Swapped `/dev/urandom` for the `getrandom` crate. Added `ZeroizeOnDrop` on handshake state (chaining key, hash, PSK). `encrypt()` returns `Option` instead of panicking on nonce exhaustion. `O_CLOEXEC` on all file descriptors.

### Phase 3: Zero-Config Enrollment

**Commit 7 — serve + join**

The standard WireGuard setup flow (generate keys on both sides, exchange public keys, assign IPs, write config files) is painful for homelabs. Built a new `rustguard-enroll` crate with a custom enrollment protocol: token-derived XChaCha20 key encrypts the key exchange, CIDR-based IP pool allocator (server gets .1, clients get sequential IPs).

```
# Server
rustguard serve --pool 10.150.0.0/24 --token mysecret

# Client (any machine)
rustguard join 1.2.3.4:51820 --token mysecret
```

No config files. No manual key exchange. No IP planning. Backward compatible — `rustguard up wg0.conf` still works.

**Commit 8 — Zigbee-style pairing window**

Enrollment always-open felt wrong. Added a UNIX domain control socket for runtime management. Server starts with enrollment closed. Physical presence model:

```
rustguard open 60      # open enrollment for 60 seconds
rustguard close        # close immediately
rustguard status       # show window state + peer count
```

Window auto-closes on expiry via atomic timestamp. Existing peers unaffected.

**Commit 9 — Persistence + benchmarks**

Server state (peer keys, assigned IPs) persisted to `~/.rustguard/state.json`. Survives restarts. Added benchmark infrastructure.

### Phase 4: Performance

The interesting part. Test rig: two Debian 12 VMs on an n305 hypervisor, Intel i225 2.5G NICs passed through (`enp7s0`, `192.168.99.1/2`). All benchmarks with `iperf3`, single TCP stream unless noted.

**Baseline (no VPN):** 2,356 Mbps
**Kernel WireGuard:** 1,096 Mbps (46.5% of wire speed)

**Commit 10 — Lock optimization**

Replaced global Mutex with `RwLock` for peer table (concurrent reads for packet routing) and per-peer `Mutex` for session state. `Arc<EnrolledPeer>` for lock-free references after lookup. In-place AEAD (`seal_to` / `open_to`) to avoid heap allocation per packet.

*Result: 175 Mbps.* TUN syscall overhead dominates, not locking.

**Commit 11 — recvmmsg batched UDP**

`recvmmsg` with `MSG_WAITFORONE` — receive up to 32 datagrams per syscall on the inbound path. macOS fallback to single `recvfrom`.

*Result: 173 Mbps.* Confirmed: TUN read/write is the bottleneck, not UDP.

**Commit 12 — AF_XDP zero-copy sockets**

Built a full AF_XDP stack: UMEM allocation (mmap'd shared memory), RX/TX/Fill/Completion ring buffers with atomics, `XDP_USE_NEED_WAKEUP` for minimal syscalls, frame pool for TX buffers. All unsafe contained behind a safe Rust API.

**Commit 13 — BPF loader + XDP filter**

Wrote a minimal BPF ELF loader (no libbpf dependency) that parses section headers, extracts programs, and patches map relocations. The XDP program filters WireGuard packets (UDP port 51820, message types 1-4) and redirects them to the AF_XDP socket. Non-WireGuard traffic passes through the kernel stack normally.

**Commit 14 — AF_XDP wired into the server**

`rustguard serve --pool 10.150.0.0/24 --token s --xdp enp7s0` — the full pipeline. BPF program loaded, XDP filter attached, AF_XDP socket receiving WireGuard packets zero-copy.

**Commit 15 — BPF ELF relocation fix**

The BPF loader's relocation patching was broken on real hardware (worked in VMs by luck). Fixed the ELF section parsing to correctly patch map FD references in BPF instructions.

*AF_XDP result: ~175 Mbps.* Same as before — TUN is still the bottleneck. UDP path is now zero-copy but it doesn't matter when the slow side is TUN read/write syscalls.

**Commit 16 — Multi-queue TUN**

`IFF_MULTI_QUEUE` on Linux opens N TUN file descriptors for the same interface. N outbound worker threads, each with its own TUN fd and UDP socket. Inbound still single-threaded (one UDP recv loop dispatching to peers).

```
rustguard serve --pool 10.150.0.0/24 --token s --queues 2
```

*Result: **472 Mbps** with 2 queues.* Nearly 3× improvement. This is the real win — parallelizing TUN I/O across cores.

**Commit 17 — io_uring TUN engine**

Replaced blocking `read()`/`write()` on TUN fds with io_uring. Pre-registered buffer pool (256 slots × 2KB). Pre-fill SQ with `ReadFixed` SQEs. On completion: process packet, push `WriteFixed` SQE. One `io_uring_enter()` per batch instead of per packet.

*Result: 225 Mbps.* Slower than multi-queue. At 30K packets/sec, the io_uring submission overhead exceeds the savings from batching. io_uring wins at higher packet rates (small packets, many flows) but loses to raw multi-queue for bulk throughput.

### Phase 5: Kernel Module

The userspace experiments proved TUN is the bottleneck. The only way to close the gap: stop leaving the kernel.

**Commit 18-28 — Rust kernel module**

Built an out-of-tree Linux kernel module in Rust targeting 6.10+:

- **`no_std` refactor**: Made `rustguard-crypto` and `rustguard-core` dual `std`/`no_std` with feature flags. Handshake functions got `_with` variants that accept explicit RNG and timestamps instead of relying on `OsRng`/`SystemTime`.

- **C shim architecture**: The kernel's Rust bindings (6.12) don't expose networking or crypto APIs. Solution: thin C shim files handle `net_device` registration (`wg_net.c`), crypto (`wg_crypto.c`), and UDP sockets (`wg_socket.c`). Rust handles the WireGuard protocol logic and packet routing.

- **Crypto**: Uses the kernel's own `chacha20poly1305` library (same functions Jason uses in the C WireGuard module) — not the kernel crypto API. Direct buffer-oriented calls, no scatterlists, no TFM allocation on the hot path.

- **Net device**: Registers `wg0` as a `POINTOPOINT | NOARP` interface with MTU 1420. `ndo_start_xmit` calls into Rust for encryption. UDP `encap_rcv` callback calls into Rust for decryption.

- **The `skb_linearize` lesson**: Large packets (full MSS TCP segments) arrive in fragmented skbs. Reading `skb->data` only gets the linear portion. One line of `skb_linearize()` before decryption fixed the AEAD authentication failures that killed TCP bulk throughput.

### Performance Summary

#### Userspace (Intel i225 2.5G NICs, PCIe passthrough, physical Ethernet)

| Configuration | Throughput | % of Wire Speed |
|---|---|---|
| Bare metal (no VPN) | 2,356 Mbps | 100% |
| Kernel WireGuard | 1,096 Mbps | 46.5% |
| **RustGuard (2 queues)** | **472 Mbps** | **20.0%** |
| RustGuard (io_uring) | 225 Mbps | 9.6% |
| RustGuard (single queue) | 175 Mbps | 7.4% |

#### Kernel Module (virtio-net VMs, same hypervisor)

| Configuration | Throughput | % of Wire Speed |
|---|---|---|
| Bare wire (virtio-net) | 33,100 Mbps | 100% |
| Kernel WireGuard (C) | 4,190 Mbps | 12.7% |
| **RustGuard kmod** | **1,180 Mbps** | **3.6%** |

The kernel module is a first pass — single-threaded, memcpy to stack buffers, no parallel crypto. Kernel WireGuard has parallel per-CPU crypto workqueues, zero-copy skb manipulation, and 10 years of optimization. The 3.5x gap is entirely engineering, not architecture. The known fixes: encrypt directly in skb scatter-gather (eliminate double memcpy), parallel crypto workqueue, NAPI-based receive.

The fundamental result: **going from userspace (TUN) to kernel (net_device) gave a 2.5x throughput improvement** — from 472 Mbps to 1,180 Mbps — confirming that TUN was always the bottleneck.

## Usage

### Standard mode (wg.conf compatible)

```bash
rustguard up /etc/wireguard/wg0.conf
```

### Zero-config mode

```bash
# Server
rustguard serve --pool 10.150.0.0/24 --token <shared-secret> --port 51820

# Client
rustguard join 203.0.113.1:51820 --token <shared-secret>

# Manage enrollment
rustguard open 60    # accept new peers for 60 seconds
rustguard close      # stop accepting
rustguard status     # show peers and window state
```

### Key management

```bash
rustguard genkey                        # generate private key
rustguard genkey | rustguard pubkey     # derive public key
```

### Performance flags (Linux only)

```bash
rustguard serve --pool 10.150.0.0/24 --token s --queues 2      # multi-queue TUN
rustguard serve --pool 10.150.0.0/24 --token s --xdp enp7s0    # AF_XDP zero-copy
rustguard serve --pool 10.150.0.0/24 --token s --uring          # io_uring batched I/O
```

## Footprint

**9,300+ lines of Rust** across 7 crates + **751 lines of C** kernel shims.

Kernel module breakdown (2,499 lines total):

| File | Lines | Role |
|------|-------|------|
| `lib.rs` | 602 | Module init, TX/RX paths, peer management, multi-peer state |
| `noise.rs` | 481 | Full Noise_IK handshake, Curve25519 DH, BLAKE2s HKDF |
| `allowedips.rs` | 211 | IPv4/IPv6 radix trie for cryptokey routing |
| `cookie.rs` | 206 | DoS protection: MAC1/MAC2 verification, cookie reply |
| `timers.rs` | 156 | Session timers: rekey, keepalive, expiry state machine |
| `replay.rs` | 92 | Anti-replay 2048-bit sliding window |
| `wg_net.c` | 231 | net_device registration, module params, skb helpers |
| `wg_crypto.c` | 229 | Kernel crypto library wrappers + time functions |
| `wg_socket.c` | 151 | Kernel UDP socket, encap_rcv callback |
| `wg_genl.c` | 140 | Genetlink skeleton for `wg` tool compatibility |

70% Rust, 30% C. The C is pure plumbing (kernel APIs without Rust bindings yet). All protocol logic — handshake, routing, replay, timers, cookies — is Rust. For reference, kernel WireGuard is ~4,000 lines of C; we're at 2,499 (62%) with full protocol coverage.

## Building

### Userspace

```bash
cargo build --release
cargo build --release --target x86_64-unknown-linux-musl  # cross-compile
```

### Kernel module

Requires a Linux 6.10+ kernel source tree with `CONFIG_RUST=y`:

```bash
cd rustguard-kmod
make modules KDIR=/path/to/linux-source KBUILD_MODPOST_WARN=1 CONFIG_DEBUG_INFO_BTF_MODULES=
```

The Makefile stages shared crate sources, rewrites imports for Kbuild, and compiles via the kernel build system.

```bash
# Load with peer configuration
sudo insmod rustguard.ko peer_ip=0x0A0A0033 peer_port=51820 role=0 \
    peer_pubkey=<64-char-hex>

# Configure interface
sudo ip addr add 10.150.0.1/24 dev wg0
sudo ip link set wg0 up
```

## Test Infrastructure

### Userspace benchmarks
- Two Debian 12 VMs on an Intel N305 hypervisor
- Intel i225 2.5G NICs with PCIe passthrough
- Direct connection: `192.168.99.1` ↔ `192.168.99.2`

### Kernel module benchmarks
- Same VMs, virtio-net (shared memory between VMs)
- Custom kernel 6.12.74 built with `CONFIG_RUST=y` on i9-9900K WSL2
- Module cross-compiled on WSL2, deployed via scp

## What I Learned

1. **TUN is the bottleneck, not crypto.** ChaCha20-Poly1305 runs at >10 Gbps on modern CPUs. The kernel boundary crossing for TUN read/write is what kills userspace VPN throughput. Proved it by going in-kernel: 472 Mbps → 1,180 Mbps.

2. **Multi-queue TUN is the biggest userspace win.** Parallelizing TUN I/O across cores gave a 2.7× improvement. Everything else (AF_XDP, io_uring, recvmmsg) was noise in comparison.

3. **AF_XDP solves the wrong problem.** Zero-copy UDP is fast, but the bottleneck is on the TUN side. AF_XDP would matter if both sides were AF_XDP (no TUN at all), but then you're building a kernel module with extra steps. Which is what we ended up doing.

4. **Rust in the kernel works, but you're on your own for networking.** Kernel 6.12 Rust bindings only cover block devices and PHY drivers. For networking, you write C shim functions and call them from Rust via FFI. Not elegant, but it works.

5. **Jason's chacha20poly1305 library is the right abstraction.** The kernel crypto API (`crypto_alloc_aead`, scatterlists, requests) is designed for block devices and TLS. WireGuard needs buffer-in, buffer-out. Jason wrote `lib/crypto/chacha20poly1305.c` for exactly this reason. We wasted time on the crypto API before finding this.

6. **`skb_linearize` is the kernel networking rite of passage.** Large packets arrive in fragmented skbs. Reading `skb->data` only gives you the linear head. Your AEAD will fail with `EBADMSG` and you'll stare at it for an hour before realizing the data isn't contiguous. Every kernel network developer has this story.

7. **The WireGuard protocol is beautifully simple.** Noise_IK, 1-RTT handshake, 64-bit nonce counter, rotating keys. Jason Donenfeld's 4,000 lines of kernel code is an achievement in discipline. Building it from scratch is the best way to appreciate that.

8. **Security audits find real bugs.** The HMAC-BLAKE2s implementation was wrong (keyed BLAKE2s ≠ HMAC). MAC1 was checked too late. The replay window was updatable before AEAD verification. None of these showed up in functional tests.

## License

MIT OR Apache-2.0
