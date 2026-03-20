//! Enrollment server: accepts new peers, assigns IPs, runs the tunnel.
//!
//! Performance-optimized packet path:
//!   - Peers behind RwLock: concurrent reads, writes only on enrollment
//!   - Per-peer Mutex: peers don't block each other
//!   - Zero-alloc crypto: in-place encrypt/decrypt in stack buffers
//!   - recvmmsg: batch up to 32 UDP receives per syscall (Linux)
//!   - Lock released before I/O

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use rustguard_core::handshake;
use rustguard_core::messages::*;
use rustguard_crypto::{PublicKey, StaticSecret, AEAD_TAG_LEN};
use rustguard_tun::{Tun, TunConfig};

use crate::control::{self, EnrollmentWindow};
use crate::pool::IpPool;
use crate::protocol;
use crate::state::{self, PersistedPeer};

struct EnrolledPeer {
    public_key: PublicKey,
    assigned_ip: Ipv4Addr,
    state: Mutex<PeerState>,
}

struct PeerState {
    endpoint: Option<SocketAddr>,
    session: Option<rustguard_core::session::TransportSession>,
    timers: rustguard_core::timers::SessionTimers,
}

struct ServerState {
    our_static: StaticSecret,
    our_public_bytes: [u8; 32],
    token_key: [u8; 32],
    pool: Mutex<IpPool>,
    peers: RwLock<Vec<Arc<EnrolledPeer>>>,
    pending_handshakes: Mutex<Vec<(u32, std::time::Instant, handshake::InitiatorHandshake)>>,
    state_path: Option<std::path::PathBuf>,
}

pub struct ServeConfig {
    pub listen_port: u16,
    pub pool_network: Ipv4Addr,
    pub pool_prefix: u8,
    pub token: String,
    pub open_immediately: bool,
    pub state_path: Option<std::path::PathBuf>,
    /// Interface name for AF_XDP fast path. None = standard UDP socket.
    pub xdp_ifname: Option<String>,
    /// Number of TUN queues (multi-queue TUN). 0 or 1 = single queue.
    pub tun_queues: usize,
    /// Use io_uring for TUN I/O.
    pub use_uring: bool,
}

pub fn run(config: ServeConfig) -> io::Result<()> {
    let our_static = StaticSecret::random();
    let our_public = our_static.public_key();
    let our_public_bytes = *our_public.as_bytes();

    let mut pool = IpPool::new(config.pool_network, config.pool_prefix)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid pool CIDR"))?;

    let token_key = protocol::derive_token_key(&config.token);

    let tun_config = TunConfig {
        name: None,
        mtu: 1420,
        address: pool.server_addr,
        destination: pool.server_addr,
        netmask: rustguard_daemon::config::prefix_to_netmask(config.pool_prefix),
    };
    let num_queues = config.tun_queues.max(1);

    // Multi-queue TUN on Linux, single TUN elsewhere.
    #[cfg(target_os = "linux")]
    let mq_tun = if num_queues > 1 {
        Some(Arc::new(rustguard_tun::linux_mq::MultiQueueTun::create(&tun_config, num_queues)?))
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let mq_tun: Option<Arc<()>> = None;

    // Single-queue fallback (always created — used for inbound writes too).
    let tun = Arc::new(Tun::create(&tun_config)?);

    let actual_queues = match &mq_tun {
        #[cfg(target_os = "linux")]
        Some(mq) => mq.num_queues(),
        _ => 1,
    };

    println!("rustguard serve");
    println!("interface: {}", tun.name());
    println!("address: {}/{}", pool.server_addr, config.pool_prefix);
    if actual_queues > 1 {
        println!("TUN queues: {actual_queues}");
    }
    println!("listening on 0.0.0.0:{}", config.listen_port);
    println!(
        "pool: {}/{} ({} addresses available)",
        config.pool_network,
        config.pool_prefix,
        (1u32 << (32 - config.pool_prefix)) - 3
    );

    let window = control::new_window();
    if config.open_immediately {
        control::open_window(&window, 3600);
        println!("enrollment: OPEN (use `rustguard close` to lock)");
    } else {
        println!("enrollment: CLOSED (use `rustguard open` to allow peers)");
    }
    println!();

    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.listen_port)))?,
    );
    udp.set_read_timeout(Some(Duration::from_millis(500)))?;

    // Set up AF_XDP fast path if requested.
    #[cfg(target_os = "linux")]
    let xdp_state: Option<(rustguard_tun::bpf_loader::XdpProgram, rustguard_tun::xdp::XdpSocket)> =
        if let Some(ref ifname) = config.xdp_ifname {
            match setup_xdp(ifname) {
                Ok((prog, xsk)) => {
                    println!("AF_XDP: active on {ifname} (zero-copy fast path)");
                    Some((prog, xsk))
                }
                Err(e) => {
                    eprintln!("AF_XDP failed ({e}), falling back to standard UDP");
                    None
                }
            }
        } else {
            None
        };

    #[cfg(not(target_os = "linux"))]
    let xdp_state: Option<()> = None;

    let use_xdp = xdp_state.is_some();

    let peer_count = Arc::new(Mutex::new(0usize));
    let sock_path = control::start_listener(Arc::clone(&window), Arc::clone(&peer_count))?;

    // Restore persisted peers.
    let state_path = config.state_path.clone();
    let mut restored = Vec::new();
    if let Some(ref path) = state_path {
        if let Ok(persisted) = state::load(path) {
            for p in &persisted {
                pool.allocate_specific(p.assigned_ip);
                restored.push(Arc::new(EnrolledPeer {
                    public_key: PublicKey::from_bytes(p.public_key),
                    assigned_ip: p.assigned_ip,
                    state: Mutex::new(PeerState {
                        endpoint: None,
                        session: None,
                        timers: rustguard_core::timers::SessionTimers::new(),
                    }),
                }));
            }
            if !persisted.is_empty() {
                println!("restored {} peers from {}", persisted.len(), path.display());
            }
        }
    }
    *peer_count.lock().unwrap() = restored.len();

    let state = Arc::new(ServerState {
        our_static,
        our_public_bytes,
        token_key,
        pool: Mutex::new(pool),
        peers: RwLock::new(restored),
        pending_handshakes: Mutex::new(Vec::new()),
        state_path,
    });

    let running = Arc::new(AtomicBool::new(true));

    // ── Outbound: TUN -> encrypt -> UDP ──
    let mut outbound_threads = Vec::new();

    #[cfg(target_os = "linux")]
    if config.use_uring {
        // io_uring outbound: batched TUN reads in a single thread.
        let state_out = Arc::clone(&state);
        let udp_out = Arc::clone(&udp);
        let running_out = Arc::clone(&running);
        let tun_clone = Arc::clone(&tun);

        println!("io_uring: active (batched TUN I/O)");

        outbound_threads.push(thread::spawn(move || {
            let mut uring = match rustguard_tun::uring::UringTun::new(
                // Get the raw fd from the Tun. We access it via a small helper.
                tun_clone.raw_fd(),
            ) {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("io_uring init failed: {e}");
                    return;
                }
            };

            let mut ct_buf = [0u8; 1500 + AEAD_TAG_LEN + TRANSPORT_HEADER_SIZE];

            while running_out.load(Ordering::Relaxed) {
                let completions = match uring.submit_and_wait(1) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                for comp in completions {
                    if !comp.is_read || comp.result <= 0 {
                        uring.bufs.free(comp.buf_idx);
                        continue;
                    }

                    let n = comp.result as usize;
                    let pkt = uring.bufs.slot(comp.buf_idx);

                    if n < 20 {
                        uring.bufs.free(comp.buf_idx);
                        continue;
                    }

                    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

                    let peers = state_out.peers.read().unwrap();
                    let peer = peers.iter().find(|p| p.assigned_ip == dst_ip);
                    let peer = match peer {
                        Some(p) => Arc::clone(p),
                        None => { uring.bufs.free(comp.buf_idx); continue; }
                    };
                    drop(peers);

                    let mut ps = peer.state.lock().unwrap();
                    let (endpoint, their_index) = match (&ps.endpoint, &ps.session) {
                        (Some(ep), Some(s)) => (*ep, s.their_index),
                        _ => { uring.bufs.free(comp.buf_idx); continue; }
                    };

                    let session = ps.session.as_mut().unwrap();
                    if let Some((counter, ct_len)) = session.encrypt_to(
                        &pkt[..n],
                        &mut ct_buf[TRANSPORT_HEADER_SIZE..],
                    ) {
                        drop(ps);
                        ct_buf[0..4].copy_from_slice(&MSG_TRANSPORT.to_le_bytes());
                        ct_buf[4..8].copy_from_slice(&their_index.to_le_bytes());
                        ct_buf[8..16].copy_from_slice(&counter.to_le_bytes());
                        let total = TRANSPORT_HEADER_SIZE + ct_len;
                        let _ = udp_out.send_to(&ct_buf[..total], endpoint);
                    } else {
                        drop(ps);
                    }

                    uring.bufs.free(comp.buf_idx);
                }
            }
        }));
    }

    // Standard outbound workers (when not using io_uring).
    #[allow(unused_variables)]
    let skip_standard = {
        #[cfg(target_os = "linux")]
        { config.use_uring }
        #[cfg(not(target_os = "linux"))]
        { false }
    };

    if !skip_standard {
    for queue_id in 0..actual_queues {
        let state_out = Arc::clone(&state);
        let udp_out = Arc::clone(&udp);
        let running_out = Arc::clone(&running);

        #[cfg(target_os = "linux")]
        let mq_clone = mq_tun.clone();
        let tun_clone = Arc::clone(&tun);

        outbound_threads.push(thread::spawn(move || {
            let mut pkt_buf = [0u8; 1500];
            let mut ct_buf = [0u8; 1500 + AEAD_TAG_LEN + TRANSPORT_HEADER_SIZE];
            while running_out.load(Ordering::Relaxed) {
                // Read from multi-queue TUN if available, else single TUN.
                let n;
                #[cfg(target_os = "linux")]
                {
                    n = if let Some(ref mq) = mq_clone {
                        match mq.read_queue(queue_id, &mut pkt_buf) {
                            Ok(n) => n,
                            Err(_) => continue,
                        }
                    } else {
                        match tun_clone.read(&mut pkt_buf) {
                            Ok(n) => n,
                            Err(_) => continue,
                        }
                    };
                }
                #[cfg(not(target_os = "linux"))]
                {
                    n = match tun_clone.read(&mut pkt_buf) {
                        Ok(nn) => nn,
                        Err(_) => continue,
                    };
                }

                if n < 20 {
                    continue;
                }

                let dst_ip = Ipv4Addr::new(pkt_buf[16], pkt_buf[17], pkt_buf[18], pkt_buf[19]);

                let peers = state_out.peers.read().unwrap();
                let peer = peers.iter().find(|p| p.assigned_ip == dst_ip);
                let Some(peer) = peer else { continue };
                let peer = Arc::clone(peer);
                drop(peers);

                let mut ps = peer.state.lock().unwrap();
                let (endpoint, their_index) = match (&ps.endpoint, &ps.session) {
                    (Some(ep), Some(s)) => (*ep, s.their_index),
                    _ => continue,
                };

                let session = ps.session.as_mut().unwrap();
                let Some((counter, ct_len)) = session.encrypt_to(&pkt_buf[..n], &mut ct_buf[TRANSPORT_HEADER_SIZE..]) else {
                    continue;
                };
                drop(ps);

                ct_buf[0..4].copy_from_slice(&MSG_TRANSPORT.to_le_bytes());
                ct_buf[4..8].copy_from_slice(&their_index.to_le_bytes());
                ct_buf[8..16].copy_from_slice(&counter.to_le_bytes());
                let total = TRANSPORT_HEADER_SIZE + ct_len;

                let _ = udp_out.send_to(&ct_buf[..total], endpoint);
            }
        }));
    }
    } // end if !skip_standard

    // ── Inbound: UDP/XDP -> decrypt -> TUN  (+ enrollment + handshake) ──
    let tun_in = Arc::clone(&tun);
    let udp_in = Arc::clone(&udp);
    let state_in = Arc::clone(&state);
    let running_in = Arc::clone(&running);
    let window_in = Arc::clone(&window);
    let peer_count_in = Arc::clone(&peer_count);

    // Split XDP state: socket goes to inbound thread, program stays here (keeps BPF attached).
    #[cfg(target_os = "linux")]
    let (xdp_xsk, _xdp_prog) = match xdp_state {
        Some((prog, xsk)) => (Some(Arc::new(Mutex::new(xsk))), Some(prog)),
        None => (None, None),
    };
    #[cfg(not(target_os = "linux"))]
    let xdp_xsk: Option<Arc<Mutex<()>>> = None;

    let inbound = thread::spawn(move || {
        let mut batch = crate::fast_udp::RecvBatch::new();

        while running_in.load(Ordering::Relaxed) {
            // Collect packets — either from AF_XDP or standard UDP.
            let mut packets: Vec<(SocketAddr, Vec<u8>)> = Vec::new();

            #[cfg(target_os = "linux")]
            if let Some(ref xsk_mtx) = xdp_xsk {
                let xsk = xsk_mtx.lock().unwrap();
                let rx = xsk.rx_poll();
                let mut frame_addrs = Vec::new();
                for (addr, frame_data) in &rx {
                    frame_addrs.push(*addr);
                    if let Some(parsed) = crate::packet::parse_eth_udp(frame_data) {
                        packets.push((parsed.src_addr, parsed.payload.to_vec()));
                    }
                }
                drop(xsk);
                if !frame_addrs.is_empty() {
                    xsk_mtx.lock().unwrap().rx_release(&frame_addrs);
                }
            }

            // Always also check standard UDP (for enrollment, handshake, fallback).
            if let Ok(count) = crate::fast_udp::recv_batch(&udp_in, &mut batch) {
                for i in 0..count {
                    if let Some(addr) = batch.addrs[i] {
                        packets.push((addr, batch.bufs[i][..batch.lens[i]].to_vec()));
                    }
                }
            }

            for (src_addr, pkt) in &packets {
                let src_addr = *src_addr;
                let buf = pkt.as_slice();
                let n = buf.len();

                if n < 4 {
                    continue;
                }

                // ── Enrollment ──
                if n >= protocol::ENROLL_REQUEST_SIZE && buf[0..4] == [0x52, 0x47, 0x45, 0x01] {
                    if !control::is_open(&window_in) {
                        continue;
                    }
                    if let Some(client_pubkey) = protocol::parse_request(&state_in.token_key, buf) {
                        let peers = state_in.peers.read().unwrap();
                        if let Some(peer) = peers.iter().find(|p| *p.public_key.as_bytes() == client_pubkey) {
                            let offer = protocol::EnrollmentOffer {
                                server_pubkey: state_in.our_public_bytes,
                                assigned_ip: peer.assigned_ip,
                                prefix_len: state_in.pool.lock().unwrap().prefix_len,
                            };
                            let resp = protocol::build_response(&state_in.token_key, &offer);
                            let _ = udp_in.send_to(&resp, src_addr);
                            continue;
                        }
                        drop(peers);

                        let mut pool = state_in.pool.lock().unwrap();
                        let Some(assigned_ip) = pool.allocate() else { continue };
                        let prefix_len = pool.prefix_len;
                        drop(pool);

                        println!("enrolled peer {} -> {assigned_ip} ({}s remaining)",
                            base64_key(&client_pubkey), control::remaining(&window_in));

                        let offer = protocol::EnrollmentOffer {
                            server_pubkey: state_in.our_public_bytes, assigned_ip, prefix_len,
                        };
                        let _ = udp_in.send_to(&protocol::build_response(&state_in.token_key, &offer), src_addr);

                        let new_peer = Arc::new(EnrolledPeer {
                            public_key: PublicKey::from_bytes(client_pubkey),
                            assigned_ip,
                            state: Mutex::new(PeerState {
                                endpoint: Some(src_addr), session: None,
                                timers: rustguard_core::timers::SessionTimers::new(),
                            }),
                        });
                        let mut peers = state_in.peers.write().unwrap();
                        peers.push(new_peer);
                        *peer_count_in.lock().unwrap() = peers.len();
                        if let Some(ref path) = state_in.state_path {
                            let persisted: Vec<PersistedPeer> = peers.iter().map(|p| PersistedPeer {
                                public_key: *p.public_key.as_bytes(), assigned_ip: p.assigned_ip,
                            }).collect();
                            let _ = state::save(path, &persisted);
                        }
                    }
                    continue;
                }

                // ── WireGuard ──
                let msg_type = u32::from_le_bytes(buf[..4].try_into().unwrap());

                match msg_type {
                    MSG_INITIATION if n >= INITIATION_SIZE => {
                        let msg = Initiation::from_bytes(buf[..INITIATION_SIZE].try_into().unwrap());
                        let result = handshake::process_initiation(&state_in.our_static, &msg, rand_index());
                        if let Some((pk, _ts, resp, session)) = result {
                            let peers = state_in.peers.read().unwrap();
                            if let Some(peer) = peers.iter().find(|p| p.public_key == pk) {
                                let mut ps = peer.state.lock().unwrap();
                                ps.session = Some(session);
                                ps.endpoint = Some(src_addr);
                                ps.timers.session_started();
                                drop(ps);
                                let _ = udp_in.send_to(&resp.to_bytes(), src_addr);
                                println!("handshake with {} ({})", base64_key(pk.as_bytes()), peer.assigned_ip);
                            }
                        }
                    }

                    MSG_TRANSPORT if n >= TRANSPORT_HEADER_SIZE => {
                        let receiver_index = u32::from_le_bytes(buf[4..8].try_into().unwrap());
                        let counter = u64::from_le_bytes(buf[8..16].try_into().unwrap());

                        let peers = state_in.peers.read().unwrap();
                        let peer = peers.iter().find(|p| {
                            let ps = p.state.lock().unwrap();
                            ps.session.as_ref().is_some_and(|s| s.our_index == receiver_index)
                        });
                        let Some(peer) = peer else { continue };
                        let peer = Arc::clone(peer);
                        drop(peers);

                        let mut ps = peer.state.lock().unwrap();
                        ps.endpoint = Some(src_addr);
                        if let Some(session) = &mut ps.session {
                            let mut decrypt_buf = [0u8; 2048];
                            let ct = &buf[TRANSPORT_HEADER_SIZE..];
                            decrypt_buf[..ct.len()].copy_from_slice(ct);
                            if let Some(pt_len) = session.decrypt_in_place(counter, &mut decrypt_buf, ct.len()) {
                                ps.timers.packet_received();
                                drop(ps);
                                let _ = tun_in.write(&decrypt_buf[..pt_len]);
                            }
                        }
                    }

                    _ => {}
                }
            }
        }
    });

    for t in outbound_threads {
        t.join().unwrap();
    }
    inbound.join().unwrap();
    control::cleanup(&sock_path);

    // _xdp_prog drops here — detaches BPF from interface.
    Ok(())
}

fn rand_index() -> u32 {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).expect("rng");
    u32::from_le_bytes(buf)
}


fn base64_key(key: &[u8; 32]) -> String {
    use base64::prelude::*;
    BASE64_STANDARD.encode(key)
}

/// Set up AF_XDP: load BPF program, create XSK, register in XSKMAP.
#[cfg(target_os = "linux")]
fn setup_xdp(
    ifname: &str,
) -> io::Result<(
    rustguard_tun::bpf_loader::XdpProgram,
    rustguard_tun::xdp::XdpSocket,
)> {
    use rustguard_tun::bpf_loader::XdpProgram;
    use rustguard_tun::xdp::{XdpConfig, XdpSocket};

    // Load and attach BPF program.
    eprintln!("AF_XDP: loading BPF program...");
    let prog = XdpProgram::load_and_attach(ifname).map_err(|e| {
        io::Error::new(e.kind(), format!("BPF load/attach: {e}"))
    })?;
    eprintln!("AF_XDP: BPF attached to {ifname}");

    // Create AF_XDP socket.
    let xsk = XdpSocket::create(&XdpConfig {
        ifname: ifname.to_string(),
        queue_id: 0,
        frame_size: 4096,
        num_frames: 4096,
        ring_size: 2048,
    })?;

    // Register XSK in the XSKMAP so BPF redirects to it.
    prog.register_xsk(0, xsk.fd())?;

    Ok((prog, xsk))
}
