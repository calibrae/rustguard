//! The tunnel: where TUN meets UDP meets crypto.
//!
//! Three threads:
//!   1. TUN -> UDP: read IP packets from TUN, find peer by dest IP, encrypt, send UDP
//!   2. UDP -> TUN: read UDP datagrams, handshake or decrypt, write IP packets to TUN
//!   3. Timer: periodic checks for rekey, keepalive, dead sessions
//!
//! Plus signal handling for clean shutdown with route cleanup.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;

use rustguard_core::handshake;
use rustguard_core::messages::{
    Initiation, Response, Transport, INITIATION_SIZE, MSG_INITIATION, MSG_RESPONSE, MSG_TRANSPORT,
    RESPONSE_SIZE, TRANSPORT_HEADER_SIZE,
};
use rustguard_crypto::StaticSecret;
use rustguard_tun::{Tun, TunConfig};

use crate::config::Config;
use crate::peer::Peer;

/// Shared state between the tunnel threads.
struct TunnelState {
    our_static: StaticSecret,
    peers: Vec<Peer>,
    /// Maps sender_index -> handshake state. Capped and pruned.
    pending_handshakes: Vec<(u32, std::time::Instant, handshake::InitiatorHandshake)>,
}

const MAX_PENDING_HANDSHAKES: usize = 64;
const HANDSHAKE_EXPIRY: Duration = Duration::from_secs(30);

/// Routes we've added that need cleanup on shutdown.
struct RouteEntry {
    route: String,
    interface: String,
    is_v6: bool,
}

/// Start the tunnel. Blocks until SIGINT/SIGTERM or fatal error.
pub fn run(config: Config) -> io::Result<()> {
    let our_static = StaticSecret::from_bytes(config.interface.private_key);

    // Create TUN device.
    // For point-to-point, find first v4 allowed IP as destination.
    let dest = config
        .peers
        .iter()
        .flat_map(|p| &p.allowed_ips)
        .find_map(|c| match c.addr {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .unwrap_or(Ipv4Addr::new(10, 0, 0, 2));

    let tun = Arc::new(Tun::create(&TunConfig {
        name: None,
        mtu: 1420,
        address: config.interface.address,
        destination: dest,
        netmask: config.interface.netmask,
    })?);

    println!("interface: {}", tun.name());

    // Assign IPv6 address if configured.
    if let Some((v6_addr, prefix_len)) = config.interface.address_v6 {
        let addr_str = format!("{}/{}", v6_addr, prefix_len);
        let result = assign_v6_address(tun.name(), &addr_str);
        match result {
            Ok(out) if out.status.success() => {
                println!("ipv6 address: {addr_str}");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                eprintln!("ipv6 address assignment failed: {stderr}");
            }
            Err(e) => eprintln!("ipv6 address command failed: {e}"),
        }
    }

    println!("listening on 0.0.0.0:{}", config.interface.listen_port);

    // Bind UDP socket. Set read timeout so the inbound thread can check shutdown.
    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::from((
            Ipv4Addr::UNSPECIFIED,
            config.interface.listen_port,
        )))
        .map_err(|e| io::Error::new(e.kind(), format!("bind UDP: {e}")))?,
    );
    udp.set_read_timeout(Some(Duration::from_millis(500)))?;

    // Build peer list.
    let peers: Vec<Peer> = config.peers.iter().map(Peer::from_config).collect();

    for peer in &peers {
        println!(
            "peer: {} endpoint={:?} allowed_ips={:?}",
            base64_key(peer.public_key.as_bytes()),
            peer.endpoint,
            peer.allowed_ips
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>(),
        );
    }

    // Add routes for AllowedIPs through the TUN interface.
    let tun_name = tun.name().to_string();
    let mut routes_added: Vec<RouteEntry> = Vec::new();
    for peer_config in &config.peers {
        for cidr in &peer_config.allowed_ips {
            let route = format!("{}", cidr);
            let is_v6 = cidr.addr.is_ipv6();
            let result = add_route(&route, &tun_name, is_v6);
            match result {
                Ok(out) if out.status.success() => {
                    println!("route add {route} -> {tun_name}");
                    routes_added.push(RouteEntry {
                        route,
                        interface: tun_name.clone(),
                        is_v6,
                    });
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    eprintln!("route add {route} failed: {stderr}");
                }
                Err(e) => eprintln!("route command failed: {e}"),
            }
        }
    }

    // Shutdown flag.
    let running = Arc::new(AtomicBool::new(true));
    {
        let running = Arc::clone(&running);
        ctrlc_handler(move || {
            println!("\nshutting down...");
            running.store(false, Ordering::SeqCst);
        });
    }

    let state = Arc::new(Mutex::new(TunnelState {
        our_static,
        peers,
        pending_handshakes: Vec::new(),
    }));

    // Initiate handshakes with all peers that have endpoints.
    {
        let mut st = state.lock().unwrap();
        for i in 0..st.peers.len() {
            if let Some(endpoint) = st.peers[i].endpoint {
                let sender_index = rand_index();
                let (init_msg, init_state) = handshake::create_initiation(
                    &st.our_static,
                    &st.peers[i].public_key,
                    sender_index,
                );
                st.pending_handshakes.push((sender_index, std::time::Instant::now(), init_state));
                st.peers[i].timers.last_handshake_sent =
                    Some(std::time::Instant::now());

                let wire = init_msg.to_bytes();
                if let Err(e) = udp.send_to(&wire, endpoint) {
                    eprintln!("failed to send handshake to {endpoint}: {e}");
                } else {
                    println!("sent handshake initiation to {endpoint}");
                }
            }
        }
    }

    // Thread 1: TUN -> UDP (outbound).
    let tun_out = Arc::clone(&tun);
    let udp_out = Arc::clone(&udp);
    let state_out = Arc::clone(&state);
    let running_out = Arc::clone(&running);
    let outbound = thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while running_out.load(Ordering::Relaxed) {
            let n = match tun_out.read(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    if !running_out.load(Ordering::Relaxed) {
                        break;
                    }
                    eprintln!("TUN read error: {e}");
                    continue;
                }
            };

            if n < 1 {
                continue;
            }

            // Extract destination IP from IP header.
            let dst_ip: IpAddr = match buf[0] >> 4 {
                4 if n >= 20 => {
                    IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]))
                }
                6 if n >= 40 => {
                    let mut addr = [0u8; 16];
                    addr.copy_from_slice(&buf[24..40]);
                    IpAddr::V6(Ipv6Addr::from(addr))
                }
                _ => continue, // Unknown or too short.
            };
            let mut st = state_out.lock().unwrap();

            let peer_idx = st.peers.iter().position(|p| p.allows_ip(dst_ip));
            let Some(idx) = peer_idx else {
                continue;
            };

            let peer = &mut st.peers[idx];
            let endpoint = match peer.endpoint {
                Some(ep) => ep,
                None => continue,
            };

            // Check if session is expired and needs rekey.
            if peer.session.is_some() && !peer.has_active_session() {
                peer.session = None; // Drop expired session.
            }

            if let Some(session) = &mut peer.session {
                // Check if we need a rekey.
                if peer.timers.needs_rekey(session.send_counter()) {
                    peer.timers.rekey_requested = true;
                    // TODO: trigger rekey in background.
                }

                let (counter, ciphertext) = session.encrypt(&buf[..n]);
                peer.timers.packet_sent();
                let transport = Transport {
                    receiver_index: session.their_index,
                    counter,
                    payload: ciphertext,
                };
                let wire = transport.to_bytes();
                if let Err(e) = udp_out.send_to(&wire, endpoint) {
                    eprintln!("UDP send error: {e}");
                }
            }
        }
    });

    // Thread 2: UDP -> TUN (inbound).
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
                Err(e) => {
                    if !running_in.load(Ordering::Relaxed) {
                        break;
                    }
                    eprintln!("UDP recv error: {e}");
                    continue;
                }
            };

            if n < 4 {
                continue;
            }

            let msg_type = u32::from_le_bytes(buf[..4].try_into().unwrap());

            match msg_type {
                MSG_INITIATION if n >= INITIATION_SIZE => {
                    let msg =
                        Initiation::from_bytes(buf[..INITIATION_SIZE].try_into().unwrap());
                    let mut st = state_in.lock().unwrap();
                    let responder_index = rand_index();

                    let result =
                        handshake::process_initiation(&st.our_static, &msg, responder_index);

                    if let Some((peer_pubkey, _timestamp, resp_msg, session)) = result {
                        if let Some(peer) = st
                            .peers
                            .iter_mut()
                            .find(|p| p.public_key == peer_pubkey)
                        {
                            peer.session = Some(session);
                            peer.endpoint = Some(src_addr);
                            peer.timers.session_started();
                            let wire = resp_msg.to_bytes();
                            if let Err(e) = udp_in.send_to(&wire, src_addr) {
                                eprintln!("failed to send response: {e}");
                            } else {
                                println!(
                                    "handshake complete with {} (they initiated)",
                                    base64_key(peer_pubkey.as_bytes()),
                                );
                            }
                        }
                    }
                }

                MSG_RESPONSE if n >= RESPONSE_SIZE => {
                    let msg =
                        Response::from_bytes(buf[..RESPONSE_SIZE].try_into().unwrap());
                    let mut st = state_in.lock().unwrap();

                    let pos = st
                        .pending_handshakes
                        .iter()
                        .position(|(idx, _, _)| *idx == msg.receiver_index);

                    if let Some(pos) = pos {
                        let (sender_index, _, init_state) = st.pending_handshakes.remove(pos);
                        let result = handshake::process_response(
                            init_state,
                            &st.our_static,
                            &msg,
                        );

                        if let Some(session) = result {
                            // Find peer that initiated with this sender_index.
                            if let Some(peer) = st.peers.iter_mut().find(|p| {
                                (p.endpoint.is_some() && !p.has_active_session())
                                    || p.session
                                        .as_ref()
                                        .is_some_and(|s| s.our_index == sender_index)
                            }) {
                                peer.session = Some(session);
                                peer.endpoint = Some(src_addr);
                                peer.timers.session_started();
                                println!(
                                    "handshake complete with {} (we initiated)",
                                    base64_key(peer.public_key.as_bytes()),
                                );
                            }
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
                        p.session
                            .as_ref()
                            .is_some_and(|s| s.our_index == msg.receiver_index)
                    });

                    if let Some(peer) = peer {
                        peer.endpoint = Some(src_addr);

                        if let Some(session) = &mut peer.session {
                            if let Some(plaintext) =
                                session.decrypt(msg.counter, &msg.payload)
                            {
                                peer.timers.packet_received();
                                drop(st);
                                if let Err(e) = tun_in.write(&plaintext) {
                                    eprintln!("TUN write error: {e}");
                                }
                            }
                        }
                    }
                }

                _ => {}
            }
        }
    });

    // Thread 3: Timer tick — keepalives, rekey, dead session cleanup.
    let state_timer = Arc::clone(&state);
    let udp_timer = Arc::clone(&udp);
    let running_timer = Arc::clone(&running);
    let timer = thread::spawn(move || {
        while running_timer.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));

            let mut st = state_timer.lock().unwrap();

            // Prune stale pending handshakes.
            st.pending_handshakes.retain(|(_, created, _)| created.elapsed() < HANDSHAKE_EXPIRY);

            // Collect handshake retry requests (avoids borrow conflict).
            let mut rekey_requests: Vec<(usize, SocketAddr)> = Vec::new();

            for (i, peer) in st.peers.iter_mut().enumerate() {
                // Zero dead sessions.
                if peer.timers.is_dead() && peer.session.is_some() {
                    println!(
                        "session expired for {}",
                        base64_key(peer.public_key.as_bytes()),
                    );
                    peer.session = None;
                }

                // Send keepalive if needed.
                if let Some(session) = &mut peer.session {
                    if peer.timers.needs_keepalive(peer.persistent_keepalive) {
                        if let Some(endpoint) = peer.endpoint {
                            let (counter, ciphertext) = session.encrypt(&[]);
                            peer.timers.packet_sent();
                            let transport = Transport {
                                receiver_index: session.their_index,
                                counter,
                                payload: ciphertext,
                            };
                            let wire = transport.to_bytes();
                            let _ = udp_timer.send_to(&wire, endpoint);
                        }
                    }
                }

                // Queue handshake retry if needed.
                if !peer.has_active_session()
                    && peer.timers.should_retry_handshake()
                    && !peer.timers.handshake_timed_out()
                {
                    if let Some(endpoint) = peer.endpoint {
                        rekey_requests.push((i, endpoint));
                    }
                }
            }

            // Process handshake retries outside the peer loop.
            for (idx, endpoint) in rekey_requests {
                let sender_index = rand_index();
                let (init_msg, init_state) = handshake::create_initiation(
                    &st.our_static,
                    &st.peers[idx].public_key,
                    sender_index,
                );
                // Cap pending handshakes to prevent memory exhaustion.
                if st.pending_handshakes.len() >= MAX_PENDING_HANDSHAKES {
                    st.pending_handshakes.remove(0); // Drop oldest.
                }
                st.pending_handshakes.push((sender_index, std::time::Instant::now(), init_state));
                st.peers[idx].timers.last_handshake_sent =
                    Some(std::time::Instant::now());

                let wire = init_msg.to_bytes();
                let _ = udp_timer.send_to(&wire, endpoint);
                println!(
                    "retrying handshake with {}",
                    base64_key(st.peers[idx].public_key.as_bytes()),
                );
            }
        }
    });

    // Wait for shutdown.
    outbound.join().unwrap();
    inbound.join().unwrap();
    timer.join().unwrap();

    // Clean up routes.
    println!("cleaning up routes...");
    for entry in &routes_added {
        let _ = delete_route(&entry.route, &entry.interface, entry.is_v6);
        println!("route delete {}", entry.route);
    }

    println!("shutdown complete");
    Ok(())
}

/// Generate a random u32 sender index using OS entropy.
fn rand_index() -> u32 {
    let mut buf = [0u8; 4];
    getrandom(&mut buf);
    u32::from_le_bytes(buf)
}

/// Read random bytes from the OS.
fn getrandom(buf: &mut [u8]) {
    use std::fs::File;
    use std::io::Read;
    File::open("/dev/urandom")
        .expect("failed to open /dev/urandom")
        .read_exact(buf)
        .expect("failed to read /dev/urandom");
}

/// Install a Ctrl-C / SIGTERM handler.
fn ctrlc_handler(f: impl FnOnce() + Send + 'static) {
    // Simple approach: spawn a thread that blocks on a signal.
    let f = std::sync::Mutex::new(Some(f));
    unsafe {
        libc::signal(libc::SIGINT, signal_noop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_noop as *const () as libc::sighandler_t);
    }
    thread::spawn(move || {
        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut sigset);
            libc::sigaddset(&mut sigset, libc::SIGINT);
            libc::sigaddset(&mut sigset, libc::SIGTERM);
            libc::sigprocmask(libc::SIG_BLOCK, &sigset, std::ptr::null_mut());
            let mut sig: libc::c_int = 0;
            libc::sigwait(&sigset, &mut sig);
        }
        if let Some(f) = f.lock().unwrap().take() {
            f();
        }
    });
}

extern "C" fn signal_noop(_: libc::c_int) {}

fn base64_key(key: &[u8; 32]) -> String {
    use base64::prelude::*;
    BASE64_STANDARD.encode(key)
}

/// Assign an IPv6 address to a TUN interface.
#[cfg(target_os = "macos")]
fn assign_v6_address(ifname: &str, addr: &str) -> io::Result<std::process::Output> {
    Command::new("ifconfig")
        .args([ifname, "inet6", addr])
        .output()
}

#[cfg(target_os = "linux")]
fn assign_v6_address(ifname: &str, addr: &str) -> io::Result<std::process::Output> {
    Command::new("ip")
        .args(["-6", "addr", "add", addr, "dev", ifname])
        .output()
}

/// Platform-specific route management.
#[cfg(target_os = "macos")]
fn add_route(route: &str, interface: &str, is_v6: bool) -> io::Result<std::process::Output> {
    let family = if is_v6 { "-inet6" } else { "-net" };
    Command::new("route")
        .args(["-n", "add", family, route, "-interface", interface])
        .output()
}

#[cfg(target_os = "macos")]
fn delete_route(route: &str, interface: &str, is_v6: bool) -> io::Result<std::process::Output> {
    let family = if is_v6 { "-inet6" } else { "-net" };
    Command::new("route")
        .args(["-n", "delete", family, route, "-interface", interface])
        .output()
}

#[cfg(target_os = "linux")]
fn add_route(route: &str, interface: &str, is_v6: bool) -> io::Result<std::process::Output> {
    let subcmd = if is_v6 { "-6" } else { "-4" };
    Command::new("ip")
        .args([subcmd, "route", "add", route, "dev", interface])
        .output()
}

#[cfg(target_os = "linux")]
fn delete_route(route: &str, interface: &str, is_v6: bool) -> io::Result<std::process::Output> {
    let subcmd = if is_v6 { "-6" } else { "-4" };
    Command::new("ip")
        .args([subcmd, "route", "del", route, "dev", interface])
        .output()
}
