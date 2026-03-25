// SPDX-License-Identifier: GPL-2.0
#![allow(dead_code)]

//! RustGuard — WireGuard kernel module in Rust.
//!
//! Full Noise_IK handshake + ChaCha20-Poly1305 transport.
//! C shims handle: net_device, kernel crypto library, UDP socket.
//! Rust handles: WireGuard protocol state machine.

use kernel::prelude::*;
use kernel::alloc::KBox;
use core::sync::atomic::{AtomicPtr, Ordering};

module! {
    type: RustGuard,
    name: "rustguard",
    author: "cali",
    description: "WireGuard VPN — Rust implementation",
    license: "GPL",
}

mod noise;
mod allowedips;
mod replay;
mod timers;
mod cookie;

// ── FFI declarations ──────────────────────────────────────────────────

/// Opaque pointer type for C interop.
pub type VoidPtr = *mut core::ffi::c_void;

extern "C" {
    // wg_net.c
    fn wg_create_device(rust_priv: VoidPtr) -> VoidPtr;
    fn wg_destroy_device(dev: VoidPtr);
    fn wg_kfree_skb(skb: VoidPtr);
    fn wg_skb_data(skb: VoidPtr, data: *mut *mut u8, len: *mut u32);
    fn wg_net_rx(dev: VoidPtr, skb: VoidPtr);
    fn wg_tx_stats(dev: VoidPtr, bytes: u32);
    fn wg_alloc_skb(len: u32) -> VoidPtr;
    fn skb_put(skb: VoidPtr, len: u32) -> *mut u8;

    // wg_crypto.c — buffer-based (for handshake, keepalive)
    fn wg_chacha20poly1305_encrypt(
        key: *const u8, nonce: u64, src: *const u8, src_len: u32,
        ad: *const u8, ad_len: u32, dst: *mut u8,
    ) -> i32;
    fn wg_chacha20poly1305_decrypt(
        key: *const u8, nonce: u64, src: *const u8, src_len: u32,
        ad: *const u8, ad_len: u32, dst: *mut u8,
    ) -> i32;
    // wg_crypto.c — zero-copy skb (for transport hot path)
    fn wg_encrypt_skb(skb: VoidPtr, plaintext_off: u32, plaintext_len: u32,
                      nonce: u64, key: *const u8) -> i32;
    fn wg_decrypt_skb(skb: VoidPtr, ct_off: u32, ct_len: u32,
                      nonce: u64, key: *const u8) -> i32;
    fn wg_crypto_init() -> i32;
    fn wg_crypto_exit();

    // wg_net.c — zero-copy skb helpers
    fn wg_skb_prepend_header(skb: VoidPtr, header_size: u32, tag_size: u32) -> VoidPtr;
    fn wg_socket_send_skb(sock: VoidPtr, skb: VoidPtr, dst_ip: u32, dst_port: u16) -> i32;

    // wg_genl.c
    fn wg_genl_init() -> i32;
    fn wg_genl_exit();

    // wg_timer.c
    fn wg_timer_start(rust_priv: VoidPtr) -> i32;
    fn wg_timer_stop();
    fn wg_curve25519_generate_secret(secret: *mut u8);
    fn wg_curve25519_generate_public(pub_key: *mut u8, secret: *const u8);
    fn wg_get_random_bytes(buf: *mut u8, len: u32);

    // wg_socket.c
    fn wg_socket_create(port: u16, rust_priv: VoidPtr) -> VoidPtr;
    fn wg_socket_destroy(sock: VoidPtr);
    fn wg_socket_send(
        sock: VoidPtr, data: *const u8, len: u32,
        dst_ip: u32, dst_port: u16,
    ) -> i32;
    fn wg_skb_len(skb: VoidPtr) -> u32;
    fn wg_skb_data_ptr(skb: VoidPtr) -> *mut u8;

    // Module params (wg_net.c)
    fn wg_param_peer_ip() -> u32;
    fn wg_param_peer_port() -> u32;
    fn wg_param_role() -> u32;
    fn wg_param_peer_pubkey(out: *mut u8) -> i32;
}

// ── Constants ─────────────────────────────────────────────────────────

/// WireGuard transport header: type(4) + receiver(4) + counter(8).
const WG_HEADER_SIZE: usize = 16;
/// AEAD authentication tag size.
pub const AEAD_TAG_SIZE: usize = 16;

// ── Per-device state ──────────────────────────────────────────────────

/// Peer configuration and session state.
struct Peer {
    /// Peer's static public key (32 bytes).
    public_key: [u8; 32],
    /// Peer's endpoint IPv4 (host byte order).
    endpoint_ip: u32,
    /// Peer's endpoint port.
    endpoint_port: u16,
    /// Pre-shared key (all zeros if not used).
    psk: [u8; 32],
    /// Active transport session (set after handshake completes).
    session: Option<noise::TransportKeys>,
    /// Previous session — kept alive during rekeying so in-flight packets decrypt.
    prev_session: Option<noise::TransportKeys>,
    /// Pending initiator handshake state (between sending init and receiving response).
    pending_handshake: Option<noise::InitiatorState>,
    /// Anti-replay window for incoming packets.
    replay_window: replay::ReplayWindow,
    /// Session timers (rekey, keepalive, expiry).
    timers: timers::SessionTimers,
    /// Client-side cookie state (for MAC2).
    cookie_state: cookie::CookieState,
    /// H3: Last received TAI64N timestamp (for handshake replay protection).
    /// Only accept initiations with a strictly greater timestamp.
    last_timestamp: [u8; 12],
}

/// Module-level device state.
struct DeviceState {
    /// Opaque pointer to C net_device.
    net_dev: VoidPtr,
    /// Opaque pointer to kernel UDP socket.
    udp_sock: VoidPtr,
    /// Our static private key.
    static_secret: [u8; 32],
    /// Our static public key.
    static_public: [u8; 32],
    /// Peers (up to MAX_PEERS). Index 0 is the first peer.
    peers: [Option<Peer>; allowedips::MAX_PEERS],
    /// Number of configured peers.
    peer_count: usize,
    /// AllowedIPs routing table.
    allowed_ips: allowedips::AllowedIps,
    /// Sender index → peer index lookup (for RX path).
    /// H5: 16-bit index space (65536 slots) to reduce collision probability.
    /// Heap-allocated via DeviceState so the ~128KB is fine.
    index_map: [Option<usize>; 65536],
    /// Cookie checker for DoS protection (server-side).
    cookie_checker: Option<cookie::CookieChecker>,
}

unsafe impl Send for DeviceState {}
unsafe impl Sync for DeviceState {}

static DEVICE_STATE_PTR: AtomicPtr<DeviceState> = AtomicPtr::new(core::ptr::null_mut());

struct RustGuard;

impl kernel::Module for RustGuard {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("rustguard: initializing\n");

        let cret = unsafe { wg_crypto_init() };
        if cret != 0 {
            pr_err!("rustguard: crypto init failed\n");
            return Err(ENOMEM);
        }

        // Generate our static keypair.
        let mut static_secret = [0u8; 32];
        let mut static_public = [0u8; 32];
        unsafe {
            wg_curve25519_generate_secret(static_secret.as_mut_ptr());
            wg_curve25519_generate_public(static_public.as_mut_ptr(), static_secret.as_ptr());
        }

        // Print full public key as hex for peer configuration.
        // In production this comes from genetlink (wg show).
        let mut hex_buf = [0u8; 64];
        for (i, b) in static_public.iter().enumerate() {
            let hi = b >> 4;
            let lo = b & 0xf;
            hex_buf[i * 2] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
            hex_buf[i * 2 + 1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
        }
        // SAFETY: hex_buf is valid ASCII.
        let hex_str = unsafe { core::str::from_utf8_unchecked(&hex_buf) };
        pr_info!("rustguard: pubkey={}\n", hex_str);

        // Allocate DeviceState on the heap to avoid kernel stack overflow (~6KB struct).
        let uninit_box = KBox::<DeviceState>::new_uninit(GFP_KERNEL)
            .map_err(|_| ENOMEM)?;
        // SAFETY: We immediately zero the memory, then overwrite all fields.
        // DeviceState is valid when zeroed (null pointers, None options, zero arrays).
        let state_raw = KBox::into_raw(uninit_box) as *mut DeviceState;
        unsafe {
            core::ptr::write_bytes(state_raw, 0, 1);
            (*state_raw).static_secret = static_secret;
            (*state_raw).static_public = static_public;
        }
        DEVICE_STATE_PTR.store(state_raw, Ordering::Release);
        let state_void = state_raw as VoidPtr;

        // Create net_device.
        let dev = unsafe { wg_create_device(state_void) };
        if dev.is_null() || is_err_ptr(dev) {
            pr_err!("rustguard: failed to create net device\n");
            unsafe { cleanup_state(state_raw) };
            return Err(ENOMEM);
        }
        unsafe { (*state_raw).net_dev = dev };

        // Create UDP socket.
        let sock = unsafe { wg_socket_create(51820, state_void) };
        if sock.is_null() || is_err_ptr(sock) {
            pr_err!("rustguard: failed to create UDP socket\n");
            unsafe { wg_destroy_device(dev); cleanup_state(state_raw) };
            return Err(ENOMEM);
        }
        unsafe { (*state_raw).udp_sock = sock };

        // Init cookie checker for DoS protection.
        unsafe {
            (*state_raw).cookie_checker = Some(cookie::CookieChecker::new(static_public));
        }

        // Register genetlink family for wg(8) tool compatibility.
        let genl_ret = unsafe { wg_genl_init() };
        if genl_ret != 0 {
            // Non-fatal — the wg tool won't work but the tunnel still functions.
            // Will fail if kernel WireGuard already registered the "wireguard" family.
            pr_info!("rustguard: genetlink registration failed ({}), wg tool unavailable\n", genl_ret);
        }

        // Configure peer from module params.
        let pip = unsafe { wg_param_peer_ip() };
        let pport = unsafe { wg_param_peer_port() } as u16;
        let role = unsafe { wg_param_role() };

        if pip != 0 {
            let mut peer_pubkey = [0u8; 32];
            let has_pubkey = unsafe { wg_param_peer_pubkey(peer_pubkey.as_mut_ptr()) } == 0;

            let peer = Peer {
                public_key: peer_pubkey,
                endpoint_ip: pip,
                endpoint_port: pport,
                psk: [0u8; 32],
                session: None,
                prev_session: None,
                pending_handshake: None,
                replay_window: replay::ReplayWindow::new(),
                timers: timers::SessionTimers::new(),
                cookie_state: cookie::CookieState::new(),
                last_timestamp: [0u8; 12],
            };

            unsafe {
                (*state_raw).peers[0] = Some(peer);
                (*state_raw).peer_count = 1;
                // Default route: send all traffic to this peer.
                (*state_raw).allowed_ips.insert_v4([0, 0, 0, 0], 0, 0);
                (*state_raw).allowed_ips.insert_v6([0; 16], 0, 0);
            }

            if has_pubkey {
                pr_info!("rustguard: peer {:02x}{:02x}{:02x}{:02x}... at {:x}:{}\n",
                    peer_pubkey[0], peer_pubkey[1], peer_pubkey[2], peer_pubkey[3],
                    pip, pport);
            } else {
                pr_info!("rustguard: peer at {:x}:{} (no pubkey, waiting for handshake)\n",
                    pip, pport);
            }

            // role=0: initiate handshake immediately.
            if role == 0 && has_pubkey {
                let mut idx_bytes = [0u8; 4];
                unsafe { wg_get_random_bytes(idx_bytes.as_mut_ptr(), 4) };
                let sender_index = u32::from_le_bytes(idx_bytes);

                // C2: create_initiation now returns Option — DH zero result is fatal.
                if let Some((init_msg, hs_state)) = noise::create_initiation(
                    &static_secret,
                    &static_public,
                    &peer_pubkey,
                    sender_index,
                    &[0u8; 32],
                ) {
                    unsafe {
                        wg_socket_send(
                            (*state_raw).udp_sock,
                            init_msg.as_ptr(),
                            noise::INITIATION_SIZE as u32,
                            pip, pport,
                        );
                        if let Some(ref mut p) = (*state_raw).peers[0] {
                            p.pending_handshake = Some(hs_state);
                        }
                    }
                    pr_info!("rustguard: handshake initiation sent\n");
                } else {
                    pr_err!("rustguard: handshake initiation failed (bad peer key?)\n");
                }
            }
        }

        // Start periodic timer for rekeying + keepalives.
        unsafe { wg_timer_start(state_raw as VoidPtr) };

        pr_info!("rustguard: wg0 created, listening on UDP 51820\n");
        Ok(RustGuard)
    }
}

impl Drop for RustGuard {
    fn drop(&mut self) {
        // Stop timer before tearing down state.
        unsafe { wg_timer_stop() };
        let state_raw = DEVICE_STATE_PTR.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !state_raw.is_null() {
            unsafe {
                let state = &*state_raw;
                if !state.udp_sock.is_null() {
                    wg_socket_destroy(state.udp_sock);
                }
                if !state.net_dev.is_null() {
                    wg_destroy_device(state.net_dev);
                }
                cleanup_state(state_raw);
            }
        }
        unsafe { wg_genl_exit() };
        unsafe { wg_crypto_exit() };
        pr_info!("rustguard: unloaded\n");
    }
}

unsafe fn cleanup_state(ptr: *mut DeviceState) {
    // C3: Zeroize key material before freeing.
    unsafe {
        noise::zeroize(&mut (*ptr).static_secret);
        // Zeroize peer key material too.
        for peer_slot in (*ptr).peers.iter_mut() {
            if let Some(ref mut peer) = peer_slot {
                noise::zeroize(&mut peer.psk);
                if let Some(ref mut session) = peer.session {
                    noise::zeroize(&mut session.key_send);
                    noise::zeroize(&mut session.key_recv);
                }
            }
        }
        drop(KBox::from_raw(ptr));
    }
    DEVICE_STATE_PTR.store(core::ptr::null_mut(), Ordering::Release);
}

// ── TX path ───────────────────────────────────────────────────────────

/// TX callback: encrypt plaintext and send as WireGuard transport packet.
#[no_mangle]
pub extern "C" fn rustguard_xmit(skb: VoidPtr, priv_: VoidPtr) -> i32 {
    unsafe { do_xmit(skb, priv_) }
}

unsafe fn do_xmit(skb: VoidPtr, priv_: VoidPtr) -> i32 {
    unsafe {
        let state = &*(priv_ as *const DeviceState);

        let mut data_ptr: *mut u8 = core::ptr::null_mut();
        let mut data_len: u32 = 0;
        wg_skb_data(skb, &mut data_ptr, &mut data_len);

        if data_ptr.is_null() || data_len == 0 {
            wg_kfree_skb(skb);
            return 0;
        }

        let plaintext = core::slice::from_raw_parts(data_ptr, data_len as usize);

        // AllowedIPs lookup.
        let peer_idx = match state.allowed_ips.lookup_packet(plaintext) {
            Some(idx) => idx,
            None => { wg_kfree_skb(skb); return 0; }
        };
        let peer = match &state.peers[peer_idx] {
            Some(p) => p,
            None => { wg_kfree_skb(skb); return 0; }
        };
        let session = match &peer.session {
            Some(s) => s,
            None => { wg_kfree_skb(skb); return 0; }
        };

        // C5: session expiry check.
        let current_counter = session.send_counter.load(Ordering::Relaxed);
        if peer.timers.is_expired(current_counter) {
            wg_kfree_skb(skb);
            return 0;
        }

        // Zero-copy path: build transport skb from plaintext skb.
        // wg_skb_prepend_header copies plaintext into a new skb with header + tag room.
        let tx_skb = wg_skb_prepend_header(
            skb, WG_HEADER_SIZE as u32, AEAD_TAG_SIZE as u32,
        );
        wg_kfree_skb(skb); // free original plaintext skb

        if tx_skb.is_null() { return 0; }

        // Write WireGuard header into the first 16 bytes.
        let counter = session.send_counter.fetch_add(1, Ordering::Relaxed);
        let hdr = wg_skb_data_ptr(tx_skb);
        let hdr_slice = core::slice::from_raw_parts_mut(hdr, WG_HEADER_SIZE);
        hdr_slice[0..4].copy_from_slice(&noise::MSG_TRANSPORT.to_le_bytes());
        hdr_slice[4..8].copy_from_slice(&session.their_index.to_le_bytes());
        hdr_slice[8..16].copy_from_slice(&counter.to_le_bytes());

        // Encrypt in-place: the plaintext starts at offset WG_HEADER_SIZE.
        let ret = wg_encrypt_skb(
            tx_skb,
            WG_HEADER_SIZE as u32,
            data_len,
            counter,
            session.key_send.as_ptr(),
        );

        if ret != 0 {
            wg_kfree_skb(tx_skb);
            return 0;
        }

        // Send the encrypted skb via UDP.
        wg_socket_send_skb(
            state.udp_sock, tx_skb,
            peer.endpoint_ip, peer.endpoint_port,
        );
        wg_kfree_skb(tx_skb);

        wg_tx_stats(state.net_dev, data_len);

        0
    }
}

// ── RX path ───────────────────────────────────────────────────────────

/// RX callback: handle incoming WireGuard messages (handshake or transport).
/// src_ip and src_port are in host byte order, extracted from the IP/UDP headers.
#[no_mangle]
pub extern "C" fn rustguard_rx(skb: VoidPtr, priv_: VoidPtr, src_ip: u32, src_port: u16) -> i32 {
    unsafe { do_rx(skb, priv_, src_ip, src_port) }
}

// SAFETY: C1 concurrency model.
// The RX path runs from encap_rcv which holds the UDP socket lock, so RX is
// effectively single-threaded. We use a raw pointer to DeviceState and obtain
// &mut references to individual peers only when needed. The TX path (do_xmit)
// only reads DeviceState through a shared reference — it reads session keys and
// atomically increments send_counter. Handshake state writes (session install,
// index_map, replay_window reset) only happen in RX context.
// index_map: writes only during handshake (rare), reads on every RX packet.
// peer.replay_window: exclusive to RX (socket lock serialization).
unsafe fn do_rx(skb: VoidPtr, priv_: VoidPtr, src_ip: u32, src_port: u16) -> i32 {
    unsafe {
        let state = priv_ as *mut DeviceState;

        let pkt_len = wg_skb_len(skb) as usize;
        let pkt_data = wg_skb_data_ptr(skb);

        if pkt_len < 4 || pkt_data.is_null() {
            wg_kfree_skb(skb);
            return 0;
        }

        let pkt = core::slice::from_raw_parts(pkt_data, pkt_len);
        let msg_type = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);

        match msg_type {
            noise::MSG_INITIATION => {
                handle_initiation(state, pkt, pkt_len, src_ip, src_port);
                wg_kfree_skb(skb);
            }
            noise::MSG_RESPONSE => {
                handle_response(state, pkt, pkt_len, src_ip, src_port);
                wg_kfree_skb(skb);
            }
            3 => {
                // Cookie Reply (type 3) — update our cookie state.
                handle_cookie_reply(state, pkt, pkt_len);
                wg_kfree_skb(skb);
            }
            noise::MSG_TRANSPORT => {
                handle_transport(state, skb, pkt, pkt_len, src_ip, src_port);
            }
            _ => {
                wg_kfree_skb(skb);
            }
        }

        0
    }
}

/// Handle handshake initiation (type 1) — we are the responder.
/// SAFETY: Called only from do_rx with socket lock held (single-threaded RX).
unsafe fn handle_initiation(
    state: *mut DeviceState, pkt: &[u8], pkt_len: usize,
    src_ip: u32, src_port: u16,
) {
    unsafe {
        if pkt_len < noise::INITIATION_SIZE { return; }

        let msg: &[u8; noise::INITIATION_SIZE] =
            pkt[..noise::INITIATION_SIZE].try_into().unwrap_or(&[0u8; noise::INITIATION_SIZE]);

        let mut idx_bytes = [0u8; 4];
        wg_get_random_bytes(idx_bytes.as_mut_ptr(), 4);
        let responder_index = u32::from_le_bytes(idx_bytes);

        // Cookie DoS protection: if under load, require valid MAC2.
        if let Some(ref mut checker) = (*state).cookie_checker {
            // Encode source address for cookie MAC.
            let mut addr_buf = [0u8; 6];
            addr_buf[0..4].copy_from_slice(&src_ip.to_be_bytes());
            addr_buf[4..6].copy_from_slice(&src_port.to_be_bytes());

            if checker.under_load {
                // Verify MAC2 (bytes 132..148) over msg[..132].
                if pkt_len >= 148 && !checker.verify_mac2(&pkt[..132], &pkt[132..148], &addr_buf) {
                    // Send cookie reply so the initiator can retry with valid MAC2.
                    let mac1: [u8; 16] = pkt[116..132].try_into().unwrap_or([0; 16]);
                    let sender_idx = u32::from_le_bytes(pkt[4..8].try_into().unwrap_or([0; 4]));
                    let reply = checker.create_reply(sender_idx, &mac1, &addr_buf);
                    wg_socket_send(
                        (*state).udp_sock,
                        reply.as_ptr(), 64,
                        src_ip, src_port,
                    );
                    return;
                }
            }
        }

        let psk = (*state).peers[0].as_ref().map(|p| p.psk).unwrap_or([0u8; 32]);

        let result = noise::process_initiation(
            &(*state).static_secret,
            &(*state).static_public,
            msg,
            responder_index,
            &psk,
        );

        if let Some((initiator_public, timestamp, resp, keys)) = result {
            // Find peer by public key, or use first empty slot.
            let mut target_idx: Option<usize> = None;
            for i in 0..(*state).peer_count {
                if let Some(ref p) = (*state).peers[i] {
                    if p.public_key == initiator_public || p.public_key == [0u8; 32] {
                        target_idx = Some(i);
                        break;
                    }
                }
            }
            let peer_idx = match target_idx {
                Some(i) => i,
                None => return,
            };

            // H3: Timestamp replay protection.
            if let Some(ref peer) = (*state).peers[peer_idx] {
                if peer.last_timestamp != [0u8; 12] && timestamp <= peer.last_timestamp {
                    return;
                }
            }

            pr_info!("rustguard: handshake from {:02x}{:02x}{:02x}{:02x}...\n",
                initiator_public[0], initiator_public[1],
                initiator_public[2], initiator_public[3]);

            // Send response to actual source (NAT traversal).
            wg_socket_send(
                (*state).udp_sock,
                resp.as_ptr(), noise::RESPONSE_SIZE as u32,
                src_ip, src_port,
            );

            let idx_slot = (keys.our_index as usize) & 0xFFFF;
            (*state).index_map[idx_slot] = Some(peer_idx);

            if let Some(ref mut peer) = (*state).peers[peer_idx] {
                peer.public_key = initiator_public;
                peer.endpoint_ip = src_ip;
                peer.endpoint_port = src_port;
                // Rotate sessions: current → previous.
                peer.prev_session = peer.session.take();
                peer.session = Some(keys);
                peer.replay_window = replay::ReplayWindow::new();
                peer.timers.session_started();
                peer.last_timestamp = timestamp;
                pr_info!("rustguard: session established (responder)\n");
            }
        }
    }
}

/// Handle handshake response (type 2) — we are the initiator.
/// SAFETY: Called only from do_rx with socket lock held (single-threaded RX).
unsafe fn handle_response(
    state: *mut DeviceState, pkt: &[u8], pkt_len: usize,
    src_ip: u32, src_port: u16,
) {
    unsafe {
        if pkt_len < noise::RESPONSE_SIZE { return; }

        let resp: &[u8; noise::RESPONSE_SIZE] =
            pkt[..noise::RESPONSE_SIZE].try_into().unwrap_or(&[0u8; noise::RESPONSE_SIZE]);

        // Find the peer with a pending handshake matching this response's receiver_index.
        let resp_receiver = u32::from_le_bytes(
            resp[8..12].try_into().unwrap_or([0; 4])
        );
        let mut peer_idx: Option<usize> = None;
        for i in 0..(*state).peer_count {
            if let Some(ref p) = (*state).peers[i] {
                if let Some(ref hs) = p.pending_handshake {
                    if hs.sender_index == resp_receiver {
                        peer_idx = Some(i);
                        break;
                    }
                }
            }
        }
        let pidx = match peer_idx {
            Some(i) => i,
            None => return,
        };

        let pending = (*state).peers[pidx].as_mut().unwrap().pending_handshake.take().unwrap();

        if let Some(keys) = noise::process_response(pending, &(*state).static_secret, resp) {
            let idx_slot = (keys.our_index as usize) & 0xFFFF;
            (*state).index_map[idx_slot] = Some(pidx);

            if let Some(ref mut peer) = (*state).peers[pidx] {
                peer.endpoint_ip = src_ip;
                peer.endpoint_port = src_port;
                peer.prev_session = peer.session.take();
                peer.session = Some(keys);
                peer.replay_window = replay::ReplayWindow::new();
                peer.timers.session_started();
                pr_info!("rustguard: session established (initiator)\n");
            }
        }
    }
}

/// Handle transport data (type 4) — decrypt with replay protection, inject into stack.
/// SAFETY: Called only from do_rx with socket lock held (single-threaded RX).
/// replay_window is exclusive to RX path due to socket lock serialization.
unsafe fn handle_transport(
    state: *mut DeviceState, skb: VoidPtr, pkt: &[u8], pkt_len: usize,
    src_ip: u32, src_port: u16,
) {
    unsafe {
        if pkt_len < WG_HEADER_SIZE + AEAD_TAG_SIZE {
            wg_kfree_skb(skb);
            return;
        }

        // Look up peer by receiver_index.
        let receiver_index = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        // H5: 16-bit index space.
        let idx_slot = (receiver_index as usize) & 0xFFFF;
        let peer_idx = match (*state).index_map[idx_slot] {
            Some(idx) => idx,
            None => { wg_kfree_skb(skb); return; }
        };
        let peer = match &mut (*state).peers[peer_idx] {
            Some(p) => p,
            None => { wg_kfree_skb(skb); return; }
        };
        let counter = u64::from_le_bytes([
            pkt[8], pkt[9], pkt[10], pkt[11],
            pkt[12], pkt[13], pkt[14], pkt[15],
        ]);

        if !peer.replay_window.check(counter) {
            wg_kfree_skb(skb);
            return;
        }

        let encrypted = &pkt[WG_HEADER_SIZE..];
        let encrypted_len = encrypted.len();

        let mut plaintext_buf = [0u8; 2048];
        if encrypted_len > plaintext_buf.len() {
            wg_kfree_skb(skb);
            return;
        }

        let mut decrypted = false;
        if let Some(ref session) = peer.session {
            if wg_chacha20poly1305_decrypt(
                session.key_recv.as_ptr(), counter,
                encrypted.as_ptr(), encrypted_len as u32,
                core::ptr::null(), 0, plaintext_buf.as_mut_ptr(),
            ) == 0 { decrypted = true; }
        }
        if !decrypted {
            if let Some(ref prev) = peer.prev_session {
                if wg_chacha20poly1305_decrypt(
                    prev.key_recv.as_ptr(), counter,
                    encrypted.as_ptr(), encrypted_len as u32,
                    core::ptr::null(), 0, plaintext_buf.as_mut_ptr(),
                ) == 0 { decrypted = true; }
            }
        }

        wg_kfree_skb(skb);
        if !decrypted { return; }

        peer.replay_window.update(counter);
        peer.timers.packet_received();

        if peer.endpoint_ip != src_ip || peer.endpoint_port != src_port {
            peer.endpoint_ip = src_ip;
            peer.endpoint_port = src_port;
        }

        let plaintext_len = encrypted_len - AEAD_TAG_SIZE;
        let new_skb = wg_alloc_skb(plaintext_len as u32);
        if new_skb.is_null() { return; }
        let dest = skb_put(new_skb, plaintext_len as u32);
        core::ptr::copy_nonoverlapping(plaintext_buf.as_ptr(), dest, plaintext_len);
        wg_net_rx((*state).net_dev, new_skb);
    }
}

/// Handle cookie reply (type 3) — store cookie for MAC2 on retry.
unsafe fn handle_cookie_reply(state: *mut DeviceState, pkt: &[u8], pkt_len: usize) {
    unsafe {
        if pkt_len < 64 { return; }

        let receiver_index = u32::from_le_bytes(pkt[4..8].try_into().unwrap_or([0; 4]));

        // Find the peer that sent the handshake with this sender_index.
        let idx_slot = (receiver_index as usize) & 0xFFFF;
        let peer_idx = match (*state).index_map[idx_slot] {
            Some(i) => i,
            None => return,
        };
        let peer = match &mut (*state).peers[peer_idx] {
            Some(p) => p,
            None => return,
        };

        let reply: &[u8; 64] = pkt[..64].try_into().unwrap_or(&[0u8; 64]);
        // MAC1 from our last sent initiation — we'd need to store this.
        // For now, use zeros as placeholder (cookie will still be stored).
        let our_mac1 = [0u8; 16]; // TODO: store last sent MAC1 per peer
        peer.cookie_state.process_reply(reply, &peer.public_key, &our_mac1);
    }
}

/// Device teardown callback.
#[no_mangle]
pub extern "C" fn rustguard_dev_uninit(_priv: VoidPtr) {}

/// Periodic timer callback (every 250ms) — check rekeying and keepalives.
#[no_mangle]
pub extern "C" fn rustguard_timer_tick(priv_: VoidPtr) {
    unsafe { do_timer_tick(priv_) }
}

unsafe fn do_timer_tick(priv_: VoidPtr) {
    unsafe {
        let state = priv_ as *mut DeviceState;

        for peer_idx in 0..(*state).peer_count {
            let peer = match &mut (*state).peers[peer_idx] {
                Some(p) => p,
                None => continue,
            };

            let session = match &peer.session {
                Some(s) => s,
                None => continue,
            };

            let counter = session.send_counter.load(Ordering::Relaxed);

            // Dead session — zero keys.
            if peer.timers.is_dead() {
                if let Some(ref mut s) = peer.session {
                    noise::zeroize(&mut s.key_send);
                    noise::zeroize(&mut s.key_recv);
                }
                peer.session = None;
                peer.prev_session = None;
                continue;
            }

            // Needs rekey — initiate new handshake.
            if peer.timers.needs_rekey(counter) && peer.pending_handshake.is_none() {
                initiate_rekey(state, peer_idx);
            }

            // Pending handshake — check for retry or timeout.
            if peer.pending_handshake.is_some() {
                if peer.timers.handshake_timed_out() {
                    // Give up — drop pending state.
                    peer.pending_handshake = None;
                    peer.timers.rekey_requested = false;
                } else if peer.timers.should_retry_handshake() {
                    // Retry — send a new initiation.
                    initiate_rekey(state, peer_idx);
                }
            }

            // Keepalive — send empty transport packet.
            if peer.timers.needs_keepalive() {
                send_keepalive(state, peer_idx);
            }
        }
    }
}

/// Initiate a rekey handshake for a peer.
unsafe fn initiate_rekey(state: *mut DeviceState, peer_idx: usize) {
    unsafe {
        let peer = match &mut (*state).peers[peer_idx] {
            Some(p) => p,
            None => return,
        };

        if peer.public_key == [0u8; 32] { return; }

        let mut idx_bytes = [0u8; 4];
        wg_get_random_bytes(idx_bytes.as_mut_ptr(), 4);
        let sender_index = u32::from_le_bytes(idx_bytes);

        if let Some((init_msg, hs_state)) = noise::create_initiation(
            &(*state).static_secret,
            &(*state).static_public,
            &peer.public_key,
            sender_index,
            &peer.psk,
        ) {
            wg_socket_send(
                (*state).udp_sock,
                init_msg.as_ptr(),
                noise::INITIATION_SIZE as u32,
                peer.endpoint_ip, peer.endpoint_port,
            );
            peer.pending_handshake = Some(hs_state);
            peer.timers.handshake_sent();
        }
    }
}

/// Send an empty keepalive transport packet.
unsafe fn send_keepalive(state: *mut DeviceState, peer_idx: usize) {
    unsafe {
        let peer = match &mut (*state).peers[peer_idx] {
            Some(p) => p,
            None => return,
        };
        let session = match &peer.session {
            Some(s) => s,
            None => return,
        };

        // Empty transport: header + AEAD tag over zero-length plaintext.
        let mut buf = [0u8; WG_HEADER_SIZE + AEAD_TAG_SIZE];
        let counter = session.send_counter.fetch_add(1, Ordering::Relaxed);
        buf[0..4].copy_from_slice(&noise::MSG_TRANSPORT.to_le_bytes());
        buf[4..8].copy_from_slice(&session.their_index.to_le_bytes());
        buf[8..16].copy_from_slice(&counter.to_le_bytes());

        wg_chacha20poly1305_encrypt(
            session.key_send.as_ptr(), counter,
            core::ptr::null(), 0,
            core::ptr::null(), 0,
            buf.as_mut_ptr().add(WG_HEADER_SIZE),
        );

        wg_socket_send(
            (*state).udp_sock,
            buf.as_ptr(),
            (WG_HEADER_SIZE + AEAD_TAG_SIZE) as u32,
            peer.endpoint_ip, peer.endpoint_port,
        );

        peer.timers.packet_sent();
    }
}

/// Genetlink GET callback (stub — returns device info).
#[no_mangle]
pub extern "C" fn rustguard_genl_get(
    _priv_data: VoidPtr, _msg_buf: VoidPtr, _buf_len: i32,
) -> i32 {
    0
}

/// Genetlink SET callback (stub — configures peers).
#[no_mangle]
pub extern "C" fn rustguard_genl_set(
    _priv_data: VoidPtr,
    _peer_pubkey: *const u8, _endpoint_ip: u32, _endpoint_port: u16,
    _allowed_ip: *const u8, _allowed_cidr: u8, _allowed_family: u16,
) -> i32 {
    0
}

fn is_err_ptr(ptr: VoidPtr) -> bool {
    let val = ptr as isize;
    val >= -4095 && val < 0
}
