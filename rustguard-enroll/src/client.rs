//! Enrollment client: join a server with zero config.
//!
//! 1. Generate a keypair
//! 2. Send enrollment request with our pubkey
//! 3. Receive server pubkey + assigned IP
//! 4. Configure TUN and start normal WireGuard tunnel

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustguard_core::handshake;
use rustguard_core::messages::*;
use rustguard_core::session::TransportSession;
use rustguard_crypto::{PublicKey, StaticSecret};
use rustguard_tun::{Tun, TunConfig};

use crate::protocol;

pub struct JoinConfig {
    pub server_endpoint: SocketAddr,
    pub token: String,
}

pub fn run(config: JoinConfig) -> io::Result<()> {
    let our_static = StaticSecret::random();
    let our_public = our_static.public_key();
    let our_public_bytes = *our_public.as_bytes();

    let token_key = protocol::derive_token_key(&config.token);

    println!("rustguard join");
    println!("enrolling with {}...", config.server_endpoint);

    // Bind a local UDP socket.
    let udp = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    udp.set_read_timeout(Some(Duration::from_secs(5)))?;

    // Send enrollment request.
    let req = protocol::build_request(&token_key, &our_public_bytes);
    udp.send_to(&req, config.server_endpoint)?;

    // Wait for response.
    let mut buf = [0u8; 256];
    let (n, _) = udp.recv_from(&mut buf).map_err(|e| {
        io::Error::new(e.kind(), format!("enrollment timeout — is the server running? ({e})"))
    })?;

    let offer = protocol::parse_response(&token_key, &buf[..n]).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid enrollment response — wrong token?")
    })?;

    let server_public = PublicKey::from_bytes(offer.server_pubkey);

    println!("enrolled!");
    println!("  server pubkey: {}", base64_key(&offer.server_pubkey));
    println!("  assigned IP: {}/{}", offer.assigned_ip, offer.prefix_len);
    println!();

    // Create TUN with assigned address.
    let netmask = rustguard_daemon::config::prefix_to_netmask(offer.prefix_len);
    let tun = Arc::new(Tun::create(&TunConfig {
        name: None,
        mtu: 1420,
        address: offer.assigned_ip,
        destination: Ipv4Addr::from(
            u32::from(offer.assigned_ip) & u32::from(netmask) | 1, // server is .1
        ),
        netmask,
    })?);

    println!("interface: {}", tun.name());

    // Add route for the pool network through the TUN.
    let route_cidr = format!(
        "{}/{}",
        Ipv4Addr::from(u32::from(offer.assigned_ip) & u32::from(netmask)),
        offer.prefix_len
    );
    add_route(&route_cidr, tun.name());

    // Drop the enrollment socket timeout — we'll reuse it for the tunnel.
    udp.set_read_timeout(Some(Duration::from_millis(500)))?;
    let udp = Arc::new(udp);

    let running = Arc::new(AtomicBool::new(true));

    // Session state.
    let session: Arc<Mutex<Option<TransportSession>>> = Arc::new(Mutex::new(None));
    let endpoint = config.server_endpoint;

    // Initiate WireGuard handshake.
    {
        let sender_index = rand_index();
        let (init_msg, init_state) =
            handshake::create_initiation(&our_static, &server_public, sender_index);
        udp.send_to(&init_msg.to_bytes(), endpoint)?;
        println!("sent handshake initiation...");

        // Wait for response.
        udp.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut resp_buf = [0u8; 256];
        let (n, _) = udp.recv_from(&mut resp_buf)?;

        if n >= RESPONSE_SIZE {
            let resp = Response::from_bytes(resp_buf[..RESPONSE_SIZE].try_into().unwrap());
            if let Some(sess) = handshake::process_response(init_state, &our_static, &resp) {
                *session.lock().unwrap() = Some(sess);
                println!("handshake complete — tunnel is up!");
                println!();
            } else {
                return Err(io::Error::new(io::ErrorKind::Other, "handshake failed"));
            }
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid handshake response"));
        }
    }

    udp.set_read_timeout(Some(Duration::from_millis(500)))?;

    // Outbound: TUN -> UDP.
    let tun_out = Arc::clone(&tun);
    let udp_out = Arc::clone(&udp);
    let session_out = Arc::clone(&session);
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

            let mut sess = session_out.lock().unwrap();
            if let Some(session) = sess.as_mut() {
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
    });

    // Inbound: UDP -> TUN.
    let tun_in = Arc::clone(&tun);
    let udp_in = Arc::clone(&udp);
    let session_in = Arc::clone(&session);
    let running_in = Arc::clone(&running);
    let inbound = thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while running_in.load(Ordering::Relaxed) {
            let (n, _) = match udp_in.recv_from(&mut buf) {
                Ok(r) => r,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(_) => continue,
            };

            if n < 4 {
                continue;
            }

            let msg_type = u32::from_le_bytes(buf[..4].try_into().unwrap());
            if msg_type == MSG_TRANSPORT && n >= TRANSPORT_HEADER_SIZE {
                let msg = match Transport::from_bytes(&buf[..n]) {
                    Some(m) => m,
                    None => continue,
                };
                let mut sess = session_in.lock().unwrap();
                if let Some(session) = sess.as_mut() {
                    if let Some(plaintext) = session.decrypt(msg.counter, &msg.payload) {
                        drop(sess);
                        let _ = tun_in.write(&plaintext);
                    }
                }
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

fn add_route(cidr: &str, ifname: &str) {
    use std::process::Command;

    #[cfg(target_os = "macos")]
    let result = Command::new("route")
        .args(["-n", "add", "-net", cidr, "-interface", ifname])
        .output();

    #[cfg(target_os = "linux")]
    let result = Command::new("ip")
        .args(["route", "add", cidr, "dev", ifname])
        .output();

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result: Result<std::process::Output, io::Error> = Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("add_route not implemented for this platform"),
    ));

    match result {
        Ok(out) if out.status.success() => println!("route add {cidr} -> {ifname}"),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            eprintln!("route add failed: {stderr}");
        }
        Err(e) => eprintln!("route command failed: {e}"),
    }
}
