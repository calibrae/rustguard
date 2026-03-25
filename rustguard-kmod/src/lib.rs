// SPDX-License-Identifier: GPL-2.0

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

#[allow(dead_code)]
mod noise;
#[allow(dead_code)]
mod allowedips;
#[allow(dead_code)]
mod replay;

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

    // wg_crypto.c
    fn wg_chacha20poly1305_encrypt(
        key: *const u8, nonce: u64, src: *const u8, src_len: u32,
        ad: *const u8, ad_len: u32, dst: *mut u8,
    ) -> i32;
    fn wg_chacha20poly1305_decrypt(
        key: *const u8, nonce: u64, src: *const u8, src_len: u32,
        ad: *const u8, ad_len: u32, dst: *mut u8,
    ) -> i32;
    fn wg_crypto_init() -> i32;
    fn wg_crypto_exit();
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
    /// Pending initiator handshake state (between sending init and receiving response).
    pending_handshake: Option<noise::InitiatorState>,
    /// Anti-replay window for incoming packets.
    replay_window: replay::ReplayWindow,
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
    index_map: [Option<usize>; 256],
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
                pending_handshake: None,
                replay_window: replay::ReplayWindow::new(),
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

                let (init_msg, hs_state) = noise::create_initiation(
                    &static_secret,
                    &static_public,
                    &peer_pubkey,
                    sender_index,
                    &[0u8; 32],
                );

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
            }
        }

        pr_info!("rustguard: wg0 created, listening on UDP 51820\n");
        Ok(RustGuard)
    }
}

impl Drop for RustGuard {
    fn drop(&mut self) {
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
        unsafe { wg_crypto_exit() };
        pr_info!("rustguard: unloaded\n");
    }
}

unsafe fn cleanup_state(ptr: *mut DeviceState) {
    unsafe { drop(KBox::from_raw(ptr)) };
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

        // AllowedIPs lookup: which peer should this packet go to?
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

        let total_len = WG_HEADER_SIZE + data_len as usize + AEAD_TAG_SIZE;
        let mut buf = [0u8; 2048];
        if total_len > buf.len() {
            wg_kfree_skb(skb);
            return 0;
        }

        let counter = session.send_counter.fetch_add(1, Ordering::Relaxed);
        buf[0..4].copy_from_slice(&noise::MSG_TRANSPORT.to_le_bytes());
        buf[4..8].copy_from_slice(&session.their_index.to_le_bytes());
        buf[8..16].copy_from_slice(&counter.to_le_bytes());

        let ret = wg_chacha20poly1305_encrypt(
            session.key_send.as_ptr(), counter,
            plaintext.as_ptr(), data_len,
            core::ptr::null(), 0,
            buf.as_mut_ptr().add(WG_HEADER_SIZE),
        );

        wg_kfree_skb(skb);

        if ret != 0 { return 0; }

        wg_socket_send(
            state.udp_sock, buf.as_ptr(), total_len as u32,
            peer.endpoint_ip, peer.endpoint_port,
        );
        wg_tx_stats(state.net_dev, data_len);

        0
    }
}

// ── RX path ───────────────────────────────────────────────────────────

/// RX callback: handle incoming WireGuard messages (handshake or transport).
#[no_mangle]
pub extern "C" fn rustguard_rx(skb: VoidPtr, priv_: VoidPtr) -> i32 {
    unsafe { do_rx(skb, priv_) }
}

unsafe fn do_rx(skb: VoidPtr, priv_: VoidPtr) -> i32 {
    unsafe {
        let state = &mut *(priv_ as *mut DeviceState);

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
                handle_initiation(state, pkt, pkt_len);
                wg_kfree_skb(skb);
            }
            noise::MSG_RESPONSE => {
                handle_response(state, pkt, pkt_len);
                wg_kfree_skb(skb);
            }
            noise::MSG_TRANSPORT => {
                handle_transport(state, skb, pkt, pkt_len);
                // skb consumed by handle_transport
            }
            _ => {
                wg_kfree_skb(skb);
            }
        }

        0
    }
}

/// Handle handshake initiation (type 1) — we are the responder.
unsafe fn handle_initiation(state: &mut DeviceState, pkt: &[u8], pkt_len: usize) {
    unsafe {
        if pkt_len < noise::INITIATION_SIZE { return; }

        let msg: &[u8; noise::INITIATION_SIZE] =
            pkt[..noise::INITIATION_SIZE].try_into().unwrap_or(&[0u8; noise::INITIATION_SIZE]);

        let mut idx_bytes = [0u8; 4];
        wg_get_random_bytes(idx_bytes.as_mut_ptr(), 4);
        let responder_index = u32::from_le_bytes(idx_bytes);

        let psk = state.peers[0].as_ref().map(|p| p.psk).unwrap_or([0u8; 32]);

        let result = noise::process_initiation(
            &state.static_secret,
            &state.static_public,
            msg,
            responder_index,
            &psk,
        );

        if let Some((initiator_public, resp, keys)) = result {
            pr_info!("rustguard: handshake from {:02x}{:02x}{:02x}{:02x}...\n",
                initiator_public[0], initiator_public[1],
                initiator_public[2], initiator_public[3]);

            if let Some(ref peer) = state.peers[0] {
                wg_socket_send(
                    state.udp_sock,
                    resp.as_ptr(), noise::RESPONSE_SIZE as u32,
                    peer.endpoint_ip, peer.endpoint_port,
                );
            }

            // Register sender index for RX lookup.
            let idx_slot = (keys.our_index as usize) & 0xFF;
            state.index_map[idx_slot] = Some(0);

            if let Some(ref mut peer) = state.peers[0] {
                peer.public_key = initiator_public;
                peer.session = Some(keys);
                peer.replay_window = replay::ReplayWindow::new();
                pr_info!("rustguard: session established (responder)\n");
            }
        }
    }
}

/// Handle handshake response (type 2) — we are the initiator.
unsafe fn handle_response(state: &mut DeviceState, pkt: &[u8], pkt_len: usize) {
    if pkt_len < noise::RESPONSE_SIZE { return; }

    let resp: &[u8; noise::RESPONSE_SIZE] =
        pkt[..noise::RESPONSE_SIZE].try_into().unwrap_or(&[0u8; noise::RESPONSE_SIZE]);

    let pending = match state.peers[0].as_mut().and_then(|p| p.pending_handshake.take()) {
        Some(p) => p,
        None => { return; }
    };

    if let Some(keys) = noise::process_response(pending, &state.static_secret, resp) {
        let idx_slot = (keys.our_index as usize) & 0xFF;
        state.index_map[idx_slot] = Some(0);

        if let Some(ref mut peer) = state.peers[0] {
            peer.session = Some(keys);
            peer.replay_window = replay::ReplayWindow::new();
            pr_info!("rustguard: session established (initiator)\n");
        }
    }
}

/// Handle transport data (type 4) — decrypt with replay protection, inject into stack.
unsafe fn handle_transport(state: &mut DeviceState, skb: VoidPtr, pkt: &[u8], pkt_len: usize) {
    unsafe {
        if pkt_len < WG_HEADER_SIZE + AEAD_TAG_SIZE {
            wg_kfree_skb(skb);
            return;
        }

        // Look up peer by receiver_index.
        let receiver_index = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        let idx_slot = (receiver_index as usize) & 0xFF;
        let peer_idx = match state.index_map[idx_slot] {
            Some(idx) => idx,
            None => { wg_kfree_skb(skb); return; }
        };
        let peer = match &mut state.peers[peer_idx] {
            Some(p) => p,
            None => { wg_kfree_skb(skb); return; }
        };
        let session = match &peer.session {
            Some(s) => s,
            None => { wg_kfree_skb(skb); return; }
        };

        let counter = u64::from_le_bytes([
            pkt[8], pkt[9], pkt[10], pkt[11],
            pkt[12], pkt[13], pkt[14], pkt[15],
        ]);

        // Replay check BEFORE decryption (cheap).
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

        let ret = wg_chacha20poly1305_decrypt(
            session.key_recv.as_ptr(), counter,
            encrypted.as_ptr(), encrypted_len as u32,
            core::ptr::null(), 0,
            plaintext_buf.as_mut_ptr(),
        );

        wg_kfree_skb(skb);

        if ret != 0 { return; }

        // Update replay window AFTER successful AEAD verification.
        peer.replay_window.update(counter);

        let plaintext_len = encrypted_len - AEAD_TAG_SIZE;

        let new_skb = wg_alloc_skb(plaintext_len as u32);
        if new_skb.is_null() { return; }

        let dest = skb_put(new_skb, plaintext_len as u32);
        core::ptr::copy_nonoverlapping(plaintext_buf.as_ptr(), dest, plaintext_len);

        wg_net_rx(state.net_dev, new_skb);
    }
}

/// Device teardown callback.
#[no_mangle]
pub extern "C" fn rustguard_dev_uninit(_priv: VoidPtr) {}

fn is_err_ptr(ptr: VoidPtr) -> bool {
    let val = ptr as isize;
    val >= -4095 && val < 0
}
