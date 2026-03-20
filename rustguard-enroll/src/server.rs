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
}

pub fn run(config: ServeConfig) -> io::Result<()> {
    let our_static = StaticSecret::random();
    let our_public = our_static.public_key();
    let our_public_bytes = *our_public.as_bytes();

    let mut pool = IpPool::new(config.pool_network, config.pool_prefix)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid pool CIDR"))?;

    let token_key = protocol::derive_token_key(&config.token);

    let tun = Arc::new(Tun::create(&TunConfig {
        name: None,
        mtu: 1420,
        address: pool.server_addr,
        destination: pool.server_addr,
        netmask: rustguard_daemon::config::prefix_to_netmask(config.pool_prefix),
    })?);

    println!("rustguard serve");
    println!("interface: {}", tun.name());
    println!("address: {}/{}", pool.server_addr, config.pool_prefix);
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
    // Hot path: read-lock peers, find by IP, per-peer lock for encrypt, send unlocked.
    let tun_out = Arc::clone(&tun);
    let udp_out = Arc::clone(&udp);
    let state_out = Arc::clone(&state);
    let running_out = Arc::clone(&running);
    let outbound = thread::spawn(move || {
        let mut pkt_buf = [0u8; 1500];
        let mut ct_buf = [0u8; 1500 + AEAD_TAG_LEN + TRANSPORT_HEADER_SIZE];
        while running_out.load(Ordering::Relaxed) {
            let n = match tun_out.read(&mut pkt_buf) {
                Ok(n) => n,
                Err(_) => continue,
            };
            if n < 20 {
                continue;
            }

            let dst_ip = Ipv4Addr::new(pkt_buf[16], pkt_buf[17], pkt_buf[18], pkt_buf[19]);

            // Read-lock: find peer by IP. No contention with other readers.
            let peers = state_out.peers.read().unwrap();
            let peer = peers.iter().find(|p| p.assigned_ip == dst_ip);
            let Some(peer) = peer else { continue };
            let peer = Arc::clone(peer);
            drop(peers); // Release read lock immediately.

            // Per-peer lock: encrypt. Other peers aren't blocked.
            let mut ps = peer.state.lock().unwrap();
            let (endpoint, their_index) = match (&ps.endpoint, &ps.session) {
                (Some(ep), Some(s)) => (*ep, s.their_index),
                _ => continue,
            };

            let session = ps.session.as_mut().unwrap();
            let Some((counter, ct_len)) = session.encrypt_to(&pkt_buf[..n], &mut ct_buf[TRANSPORT_HEADER_SIZE..]) else {
                continue;
            };
            drop(ps); // Release peer lock before syscall.

            // Build transport header directly into buffer.
            ct_buf[0..4].copy_from_slice(&MSG_TRANSPORT.to_le_bytes());
            ct_buf[4..8].copy_from_slice(&their_index.to_le_bytes());
            ct_buf[8..16].copy_from_slice(&counter.to_le_bytes());
            let total = TRANSPORT_HEADER_SIZE + ct_len;

            let _ = udp_out.send_to(&ct_buf[..total], endpoint);
        }
    });

    // ── Inbound: UDP -> decrypt -> TUN  (+ enrollment + handshake) ──
    let tun_in = Arc::clone(&tun);
    let udp_in = Arc::clone(&udp);
    let state_in = Arc::clone(&state);
    let running_in = Arc::clone(&running);
    let window_in = Arc::clone(&window);
    let peer_count_in = Arc::clone(&peer_count);
    let inbound = thread::spawn(move || {
        let mut batch = crate::fast_udp::RecvBatch::new();
        while running_in.load(Ordering::Relaxed) {
            let count = match crate::fast_udp::recv_batch(&udp_in, &mut batch) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for pkt_idx in 0..count {
                let n = batch.lens[pkt_idx];
                let src_addr = match batch.addrs[pkt_idx] {
                    Some(a) => a,
                    None => continue,
                };
                let buf = &mut batch.bufs[pkt_idx];

            if n < 4 {
                continue;
            }

            // ── Enrollment ──
            if n >= protocol::ENROLL_REQUEST_SIZE && buf[0..4] == [0x52, 0x47, 0x45, 0x01] {
                if !control::is_open(&window_in) {
                    continue;
                }
                if let Some(client_pubkey) = protocol::parse_request(&state_in.token_key, &buf[..n]) {
                    let peers = state_in.peers.read().unwrap();
                    let existing = peers.iter().find(|p| *p.public_key.as_bytes() == client_pubkey);
                    if let Some(peer) = existing {
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
                    let Some(assigned_ip) = pool.allocate() else {
                        eprintln!("pool exhausted");
                        continue;
                    };
                    let prefix_len = pool.prefix_len;
                    drop(pool);

                    let rem = control::remaining(&window_in);
                    println!("enrolled peer {} -> {assigned_ip} ({rem}s remaining)", base64_key(&client_pubkey));

                    let offer = protocol::EnrollmentOffer {
                        server_pubkey: state_in.our_public_bytes,
                        assigned_ip,
                        prefix_len,
                    };
                    let resp = protocol::build_response(&state_in.token_key, &offer);
                    let _ = udp_in.send_to(&resp, src_addr);

                    let new_peer = Arc::new(EnrolledPeer {
                        public_key: PublicKey::from_bytes(client_pubkey),
                        assigned_ip,
                        state: Mutex::new(PeerState {
                            endpoint: Some(src_addr),
                            session: None,
                            timers: rustguard_core::timers::SessionTimers::new(),
                        }),
                    });

                    let mut peers = state_in.peers.write().unwrap();
                    peers.push(new_peer);
                    *peer_count_in.lock().unwrap() = peers.len();

                    if let Some(ref path) = state_in.state_path {
                        let persisted: Vec<PersistedPeer> = peers.iter().map(|p| PersistedPeer {
                            public_key: *p.public_key.as_bytes(),
                            assigned_ip: p.assigned_ip,
                        }).collect();
                        let _ = state::save(path, &persisted);
                    }
                }
                continue;
            }

            // ── WireGuard messages ──
            let msg_type = u32::from_le_bytes(buf[..4].try_into().unwrap());

            match msg_type {
                MSG_INITIATION if n >= INITIATION_SIZE => {
                    let msg = Initiation::from_bytes(buf[..INITIATION_SIZE].try_into().unwrap());
                    let responder_index = rand_index();

                    let result = handshake::process_initiation(
                        &state_in.our_static, &msg, responder_index,
                    );

                    if let Some((peer_pubkey, _ts, resp_msg, session)) = result {
                        let peers = state_in.peers.read().unwrap();
                        if let Some(peer) = peers.iter().find(|p| p.public_key == peer_pubkey) {
                            let mut ps = peer.state.lock().unwrap();
                            ps.session = Some(session);
                            ps.endpoint = Some(src_addr);
                            ps.timers.session_started();
                            drop(ps);
                            let _ = udp_in.send_to(&resp_msg.to_bytes(), src_addr);
                            println!("handshake with {} ({})", base64_key(peer_pubkey.as_bytes()), peer.assigned_ip);
                        }
                    }
                }

                MSG_TRANSPORT if n >= TRANSPORT_HEADER_SIZE => {
                    let receiver_index = u32::from_le_bytes(buf[4..8].try_into().unwrap());
                    let counter = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                    let ct_len = n - TRANSPORT_HEADER_SIZE;

                    // Read-lock to find peer.
                    let peers = state_in.peers.read().unwrap();
                    let peer = peers.iter().find(|p| {
                        let ps = p.state.lock().unwrap();
                        ps.session.as_ref().is_some_and(|s| s.our_index == receiver_index)
                    });
                    let Some(peer) = peer else { continue };
                    let peer = Arc::clone(peer);
                    drop(peers);

                    // Per-peer lock: decrypt in place.
                    let mut ps = peer.state.lock().unwrap();
                    ps.endpoint = Some(src_addr);

                    if let Some(session) = &mut ps.session {
                        // Decrypt directly in the receive buffer — zero alloc.
                        let payload_start = TRANSPORT_HEADER_SIZE;
                        if let Some(pt_len) = session.decrypt_in_place(
                            counter,
                            &mut buf[payload_start..],
                            ct_len,
                        ) {
                            ps.timers.packet_received();
                            drop(ps);
                            let _ = tun_in.write(&buf[payload_start..payload_start + pt_len]);
                        }
                    }
                }

                _ => {}
            }
            } // end for pkt_idx
        }
    });

    outbound.join().unwrap();
    inbound.join().unwrap();
    control::cleanup(&sock_path);
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
