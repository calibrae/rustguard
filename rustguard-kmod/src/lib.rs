// SPDX-License-Identifier: GPL-2.0

//! RustGuard — WireGuard kernel module in Rust.
//!
//! C shims handle: net_device (wg_net.c), crypto (wg_crypto.c), UDP (wg_socket.c).
//! Rust handles: WireGuard protocol logic, peer state, packet routing.

use kernel::prelude::*;

module! {
    type: RustGuard,
    name: "rustguard",
    author: "cali",
    description: "WireGuard VPN — Rust implementation",
    license: "GPL",
}

// ── FFI declarations ──────────────────────────────────────────────────

type VoidPtr = *mut core::ffi::c_void;

extern "C" {
    // wg_net.c
    fn wg_create_device(rust_priv: VoidPtr) -> VoidPtr;
    fn wg_destroy_device(dev: VoidPtr);
    fn wg_kfree_skb(skb: VoidPtr);
    fn wg_skb_data(skb: VoidPtr, data: *mut *mut u8, len: *mut u32);
    fn wg_net_rx(dev: VoidPtr, skb: VoidPtr);
    fn wg_tx_stats(dev: VoidPtr, bytes: u32);

    // wg_crypto.c
    fn wg_chacha20poly1305_encrypt(
        key: *const u8, nonce: u64, src: *const u8, src_len: u32,
        ad: *const u8, ad_len: u32, dst: *mut u8,
    ) -> i32;
    fn wg_chacha20poly1305_decrypt(
        key: *const u8, nonce: u64, src: *const u8, src_len: u32,
        ad: *const u8, ad_len: u32, dst: *mut u8,
    ) -> i32;
    fn wg_hkdf(
        key: *const u8, input: *const u8, input_len: u32,
        out1: *mut u8, out2: *mut u8, out3: *mut u8,
    );
    fn wg_blake2s_256(data: *const u8, data_len: u32, out: *mut u8);
    fn wg_blake2s_256_hmac(key: *const u8, data: *const u8, data_len: u32, out: *mut u8);
    fn wg_curve25519(out: *mut u8, scalar: *const u8, point: *const u8) -> i32;
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
    fn wg_skb_pull(skb: VoidPtr, len: u32);
    fn wg_skb_len(skb: VoidPtr) -> u32;
    fn wg_skb_data_ptr(skb: VoidPtr) -> *mut u8;
}

// ── WireGuard constants ───────────────────────────────────────────────

const WG_HEADER_SIZE: usize = 16; // type(4) + receiver(4) + counter(8)
const AEAD_TAG_SIZE: usize = 16;
const MSG_TRANSPORT: u32 = 4;

// ── Per-device state ──────────────────────────────────────────────────

/// Simplified peer — hardcoded for initial testing.
/// TODO: full peer table with AllowedIPs trie.
struct Peer {
    /// Peer's endpoint (IPv4 address in host byte order).
    endpoint_ip: u32,
    /// Peer's endpoint port.
    endpoint_port: u16,
    /// Sending key (from completed handshake).
    key_send: [u8; 32],
    /// Receiving key.
    key_recv: [u8; 32],
    /// Our sender index.
    our_index: u32,
    /// Their sender index (receiver_index in our outgoing packets).
    their_index: u32,
    /// Outgoing nonce counter.
    send_counter: u64,
}

/// Global device state — lives for the lifetime of the module.
/// This is what rust_priv points to in the C shims.
struct DeviceState {
    /// Opaque pointer to the C net_device.
    net_dev: VoidPtr,
    /// Opaque pointer to the kernel UDP socket.
    udp_sock: VoidPtr,
    /// Single peer for testing. None = no peer configured.
    peer: Option<Peer>,
}

unsafe impl Send for DeviceState {}
unsafe impl Sync for DeviceState {}

// We store the device state in a static because the C callbacks need
// to reach it from a raw pointer, and we need it to outlive the module.
static mut DEVICE_STATE: Option<DeviceState> = None;

struct RustGuard;

impl kernel::Module for RustGuard {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("rustguard: initializing\n");

        let state = DeviceState {
            net_dev: core::ptr::null_mut(),
            udp_sock: core::ptr::null_mut(),
            peer: None,
        };

        // SAFETY: single-threaded init.
        unsafe { DEVICE_STATE = Some(state) };

        let state_ptr = unsafe {
            DEVICE_STATE.as_mut().unwrap() as *mut DeviceState as VoidPtr
        };

        // Create the net_device.
        let dev = unsafe { wg_create_device(state_ptr) };
        if dev.is_null() || is_err_ptr(dev) {
            pr_err!("rustguard: failed to create net device\n");
            unsafe { DEVICE_STATE = None };
            return Err(ENOMEM);
        }
        unsafe { DEVICE_STATE.as_mut().unwrap().net_dev = dev };

        // Create UDP socket on port 51820.
        let sock = unsafe { wg_socket_create(51820, state_ptr) };
        if sock.is_null() || is_err_ptr(sock) {
            pr_err!("rustguard: failed to create UDP socket\n");
            unsafe {
                wg_destroy_device(dev);
                DEVICE_STATE = None;
            };
            return Err(ENOMEM);
        }
        unsafe { DEVICE_STATE.as_mut().unwrap().udp_sock = sock };

        pr_info!("rustguard: wg0 created, listening on UDP 51820\n");
        Ok(RustGuard)
    }
}

impl Drop for RustGuard {
    fn drop(&mut self) {
        // SAFETY: we're the only ones touching DEVICE_STATE during drop.
        unsafe {
            if let Some(ref state) = DEVICE_STATE {
                if !state.udp_sock.is_null() {
                    wg_socket_destroy(state.udp_sock);
                }
                if !state.net_dev.is_null() {
                    wg_destroy_device(state.net_dev);
                }
            }
            DEVICE_STATE = None;
        }
        pr_info!("rustguard: unloaded\n");
    }
}

// ── Packet handling ───────────────────────────────────────────────────

/// TX path: packet arrives from the kernel stack for transmission through wg0.
/// Encrypt it and send via UDP to the peer.
///
/// # Safety
/// Called from C (wg_net.c ndo_start_xmit) with valid skb and rust_priv.
#[no_mangle]
pub unsafe extern "C" fn rustguard_xmit(skb: VoidPtr, priv_: VoidPtr) -> i32 {
    let state = &*(priv_ as *const DeviceState);

    let peer = match &state.peer {
        Some(p) => p,
        None => {
            // No peer configured — drop the packet silently.
            wg_kfree_skb(skb);
            return 0; // NETDEV_TX_OK
        }
    };

    // Get plaintext data from skb.
    let mut data_ptr: *mut u8 = core::ptr::null_mut();
    let mut data_len: u32 = 0;
    wg_skb_data(skb, &mut data_ptr, &mut data_len);

    if data_ptr.is_null() || data_len == 0 {
        wg_kfree_skb(skb);
        return 0;
    }

    // Build WireGuard transport packet:
    // type(4) + receiver_index(4) + counter(8) + encrypted_payload + tag(16)
    let total_len = WG_HEADER_SIZE + data_len as usize + AEAD_TAG_SIZE;
    let mut buf = [0u8; 2048]; // stack buffer, max MTU 1420 + overhead
    if total_len > buf.len() {
        wg_kfree_skb(skb);
        return 0;
    }

    // Header: type = 4 (transport), receiver_index, counter
    let counter = peer.send_counter;
    buf[0..4].copy_from_slice(&MSG_TRANSPORT.to_le_bytes());
    buf[4..8].copy_from_slice(&peer.their_index.to_le_bytes());
    buf[8..16].copy_from_slice(&counter.to_le_bytes());

    // Encrypt plaintext into buf[16..].
    let plaintext = core::slice::from_raw_parts(data_ptr, data_len as usize);
    let ret = wg_chacha20poly1305_encrypt(
        peer.key_send.as_ptr(),
        counter,
        plaintext.as_ptr(),
        data_len,
        core::ptr::null(), 0, // no AAD for transport
        buf.as_mut_ptr().add(WG_HEADER_SIZE),
    );

    // Free the original skb — we've consumed the plaintext.
    wg_kfree_skb(skb);

    if ret != 0 {
        return 0;
    }

    // TODO: increment send_counter (need mutable access to peer)
    // For now this is read-only — counter stays at 0.

    // Send via UDP.
    wg_socket_send(
        state.udp_sock,
        buf.as_ptr(),
        total_len as u32,
        peer.endpoint_ip,
        peer.endpoint_port,
    );

    wg_tx_stats(state.net_dev, data_len);

    0 // NETDEV_TX_OK
}

/// RX path: encrypted UDP packet arrives on our socket.
/// Decrypt it and inject the plaintext into the kernel stack via wg_net_rx.
///
/// # Safety
/// Called from C (wg_socket.c encap_rcv callback) with valid skb and rust_priv.
#[no_mangle]
pub unsafe extern "C" fn rustguard_rx(skb: VoidPtr, priv_: VoidPtr) -> i32 {
    let state = &*(priv_ as *const DeviceState);

    let peer = match &state.peer {
        Some(p) => p,
        None => {
            wg_kfree_skb(skb);
            return 0;
        }
    };

    let pkt_len = wg_skb_len(skb) as usize;
    let pkt_data = wg_skb_data_ptr(skb);

    if pkt_len < WG_HEADER_SIZE + AEAD_TAG_SIZE || pkt_data.is_null() {
        wg_kfree_skb(skb);
        return 0;
    }

    let pkt = core::slice::from_raw_parts(pkt_data, pkt_len);

    // Parse header.
    let msg_type = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
    if msg_type != MSG_TRANSPORT {
        // TODO: handle handshake messages (types 1, 2, 3)
        wg_kfree_skb(skb);
        return 0;
    }

    let _receiver_index = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    let counter = u64::from_le_bytes([
        pkt[8], pkt[9], pkt[10], pkt[11],
        pkt[12], pkt[13], pkt[14], pkt[15],
    ]);

    let encrypted = &pkt[WG_HEADER_SIZE..];
    let encrypted_len = encrypted.len();

    // Decrypt in a stack buffer.
    let mut plaintext_buf = [0u8; 2048];
    if encrypted_len > plaintext_buf.len() {
        wg_kfree_skb(skb);
        return 0;
    }

    let ret = wg_chacha20poly1305_decrypt(
        peer.key_recv.as_ptr(),
        counter,
        encrypted.as_ptr(),
        encrypted_len as u32,
        core::ptr::null(), 0,
        plaintext_buf.as_mut_ptr(),
    );

    if ret != 0 {
        // Decryption failed — wrong key, tampered, or wrong counter.
        wg_kfree_skb(skb);
        return 0;
    }

    let plaintext_len = encrypted_len - AEAD_TAG_SIZE;

    // Strip the WireGuard header from the skb, replace with decrypted plaintext.
    // Easier: just pull the whole skb and push new data.
    // Actually: reuse the skb — pull header + encrypted, push plaintext.
    // Simplest: pull everything, then use skb_put + memcpy.
    //
    // For now, the crude approach: free original skb, allocate a new one.
    wg_kfree_skb(skb);

    // Allocate a fresh skb for the plaintext.
    extern "C" {
        fn wg_alloc_skb(len: u32) -> VoidPtr;
    }
    let new_skb = wg_alloc_skb(plaintext_len as u32);
    if new_skb.is_null() {
        return 0;
    }

    // skb_put + memcpy the plaintext into the new skb.
    extern "C" {
        fn skb_put(skb: VoidPtr, len: u32) -> *mut u8;
    }
    let dest = skb_put(new_skb, plaintext_len as u32);
    core::ptr::copy_nonoverlapping(plaintext_buf.as_ptr(), dest, plaintext_len);

    // Inject into the kernel network stack.
    wg_net_rx(state.net_dev, new_skb);

    0
}

/// Called by the C shim when the device is being torn down.
#[no_mangle]
pub extern "C" fn rustguard_dev_uninit(_priv: VoidPtr) {}

/// Check if a pointer is an ERR_PTR (kernel error encoded as pointer).
fn is_err_ptr(ptr: VoidPtr) -> bool {
    let val = ptr as isize;
    val >= -4095 && val < 0
}
