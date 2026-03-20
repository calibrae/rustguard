//! Enrollment server: accepts new peers, assigns IPs, runs the tunnel.
//!
//! This is the "open mode" — a WireGuard server that dynamically accepts
//! new peers via the enrollment protocol, then runs a standard tunnel.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustguard_core::handshake;
use rustguard_core::messages::*;
use rustguard_crypto::{PublicKey, StaticSecret};
use rustguard_tun::{Tun, TunConfig};

use crate::pool::IpPool;
use crate::protocol;

/// A dynamically enrolled peer.
struct EnrolledPeer {
    public_key: PublicKey,
    assigned_ip: Ipv4Addr,
    endpoint: Option<SocketAddr>,
    session: Option<rustguard_core::session::TransportSession>,
    timers: rustguard_core::timers::SessionTimers,
}

struct ServerState {
    our_static: StaticSecret,
    our_public_bytes: [u8; 32],
    token_key: [u8; 32],
    pool: IpPool,
    peers: Vec<EnrolledPeer>,
    pending_handshakes: Vec<(u32, std::time::Instant, handshake::InitiatorHandshake)>,
}

/// Configuration for the enrollment server.
pub struct ServeConfig {
    pub listen_port: u16,
    pub pool_network: Ipv4Addr,
    pub pool_prefix: u8,
    pub token: String,
}

pub fn run(config: ServeConfig) -> io::Result<()> {
    let our_static = StaticSecret::random();
    let our_public = our_static.public_key();
    let our_public_bytes = *our_public.as_bytes();

    let pool = IpPool::new(config.pool_network, config.pool_prefix)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid pool CIDR"))?;

    let token_key = protocol::derive_token_key(&config.token);

    // Create TUN with the server's pool address.
    let tun = Arc::new(Tun::create(&TunConfig {
        name: None,
        mtu: 1420,
        address: pool.server_addr,
        destination: pool.server_addr, // Will route via AllowedIPs.
        netmask: rustguard_daemon::config::prefix_to_netmask(config.pool_prefix),
    })?);

    println!("rustguard serve (open mode)");
    println!("interface: {}", tun.name());
    println!("address: {}/{}", pool.server_addr, config.pool_prefix);
    println!("listening on 0.0.0.0:{}", config.listen_port);
    println!("enrollment: active (token required)");
    println!("pool: {}/{} ({} addresses available)",
        config.pool_network, config.pool_prefix,
        (1u32 << (32 - config.pool_prefix)) - 3 // minus network, server, broadcast
    );
    println!();

    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.listen_port)))?,
    );
    udp.set_read_timeout(Some(Duration::from_millis(500)))?;

    let state = Arc::new(Mutex::new(ServerState {
        our_static,
        our_public_bytes,
        token_key,
        pool,
        peers: Vec::new(),
        pending_handshakes: Vec::new(),
    }));

    let running = Arc::new(AtomicBool::new(true));

    // Outbound: TUN -> UDP.
    let tun_out = Arc::clone(&tun);
    let udp_out = Arc::clone(&udp);
    let state_out = Arc::clone(&state);
    let running_out = Arc::clone(&running);
    let outbound = thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while running_out.load(Ordering::Relaxed) {
            let n = match tun_out.read(&mut buf) {
                Ok(n) => n,
                Err(_) => continue,
            };
            if n < 20 {
                continue;
            }

            let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
            let mut st = state_out.lock().unwrap();

            let peer = st.peers.iter_mut().find(|p| p.assigned_ip == dst_ip);
            if let Some(peer) = peer {
                if let (Some(endpoint), Some(session)) = (peer.endpoint, &mut peer.session) {
                    if let Some((counter, ciphertext)) = session.encrypt(&buf[..n]) {
                        let transport = Transport {
                            receiver_index: session.their_index,
                            counter,
                            payload: ciphertext,
                        };
                        let _ = udp_out.send_to(&transport.to_bytes(), endpoint);
                    }
                }
            }
        }
    });

    // Inbound: UDP -> TUN (handles both enrollment and WireGuard messages).
    let tun_in = Arc::clone(&tun);
    let udp_in = Arc::clone(&udp);
    let state_in = Arc::clone(&state);
    let running_in = Arc::clone(&running);
    let inbound = thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while running_in.load(Ordering::Relaxed) {
            let (n, src_addr) = match udp_in.recv_from(&mut buf) {
                Ok(r) => r,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(_) => continue,
            };

            if n < 4 {
                continue;
            }

            // Check if this is an enrollment request (our custom magic).
            if n >= protocol::ENROLL_REQUEST_SIZE && buf[0..4] == [0x52, 0x47, 0x45, 0x01] {
                let mut st = state_in.lock().unwrap();
                if let Some(client_pubkey) = protocol::parse_request(&st.token_key, &buf[..n]) {
                    // Check if already enrolled.
                    let already = st.peers.iter().any(|p| *p.public_key.as_bytes() == client_pubkey);
                    if already {
                        // Re-send the existing assignment.
                        if let Some(peer) = st.peers.iter().find(|p| *p.public_key.as_bytes() == client_pubkey) {
                            let offer = protocol::EnrollmentOffer {
                                server_pubkey: st.our_public_bytes,
                                assigned_ip: peer.assigned_ip,
                                prefix_len: st.pool.prefix_len,
                            };
                            let resp = protocol::build_response(&st.token_key, &offer);
                            let _ = udp_in.send_to(&resp, src_addr);
                        }
                        continue;
                    }

                    // Allocate IP.
                    let Some(assigned_ip) = st.pool.allocate() else {
                        eprintln!("pool exhausted — rejecting enrollment from {src_addr}");
                        continue;
                    };

                    println!(
                        "enrolled peer {} -> {assigned_ip}",
                        base64_key(&client_pubkey),
                    );

                    // Send response.
                    let offer = protocol::EnrollmentOffer {
                        server_pubkey: st.our_public_bytes,
                        assigned_ip,
                        prefix_len: st.pool.prefix_len,
                    };
                    let resp = protocol::build_response(&st.token_key, &offer);
                    let _ = udp_in.send_to(&resp, src_addr);

                    // Add as peer.
                    st.peers.push(EnrolledPeer {
                        public_key: PublicKey::from_bytes(client_pubkey),
                        assigned_ip,
                        endpoint: Some(src_addr),
                        session: None,
                        timers: rustguard_core::timers::SessionTimers::new(),
                    });
                }
                continue;
            }

            let msg_type = u32::from_le_bytes(buf[..4].try_into().unwrap());

            match msg_type {
                MSG_INITIATION if n >= INITIATION_SIZE => {
                    let msg = Initiation::from_bytes(buf[..INITIATION_SIZE].try_into().unwrap());
                    let mut st = state_in.lock().unwrap();
                    let responder_index = rand_index();

                    let result = handshake::process_initiation(
                        &st.our_static, &msg, responder_index,
                    );

                    if let Some((peer_pubkey, _ts, resp_msg, session)) = result {
                        if let Some(peer) = st.peers.iter_mut().find(|p| p.public_key == peer_pubkey) {
                            peer.session = Some(session);
                            peer.endpoint = Some(src_addr);
                            peer.timers.session_started();
                            let _ = udp_in.send_to(&resp_msg.to_bytes(), src_addr);
                            println!(
                                "handshake complete with {} ({})",
                                base64_key(peer_pubkey.as_bytes()),
                                peer.assigned_ip,
                            );
                        }
                    }
                }

                MSG_TRANSPORT if n >= TRANSPORT_HEADER_SIZE => {
                    let msg = match Transport::from_bytes(&buf[..n]) {
                        Some(m) => m,
                        None => continue,
                    };
                    let mut st = state_in.lock().unwrap();

                    let peer = st.peers.iter_mut().find(|p| {
                        p.session.as_ref().is_some_and(|s| s.our_index == msg.receiver_index)
                    });

                    if let Some(peer) = peer {
                        peer.endpoint = Some(src_addr);
                        if let Some(session) = &mut peer.session {
                            if let Some(plaintext) = session.decrypt(msg.counter, &msg.payload) {
                                peer.timers.packet_received();
                                drop(st);
                                let _ = tun_in.write(&plaintext);
                            }
                        }
                    }
                }

                _ => {}
            }
        }
    });

    outbound.join().unwrap();
    inbound.join().unwrap();
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
