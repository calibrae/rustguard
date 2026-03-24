// SPDX-License-Identifier: GPL-2.0

//! RustGuard — WireGuard kernel module in Rust.
//!
//! C shims handle: net_device (wg_net.c), crypto (wg_crypto.c), UDP (wg_socket.c).
//! Rust handles: WireGuard protocol logic, peer state, packet routing.

use kernel::prelude::*;
use kernel::alloc::KBox;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

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
}

// ── WireGuard constants ───────────────────────────────────────────────

const WG_HEADER_SIZE: usize = 16; // type(4) + receiver(4) + counter(8)
const AEAD_TAG_SIZE: usize = 16;
const MSG_TRANSPORT: u32 = 4;

// ── Per-device state ──────────────────────────────────────────────────

struct Peer {
    endpoint_ip: u32,
    endpoint_port: u16,
    key_send: [u8; 32],
    key_recv: [u8; 32],
    their_index: u32,
    send_counter: AtomicU64,
}

struct DeviceState {
    net_dev: VoidPtr,
    udp_sock: VoidPtr,
    peer: Option<Peer>,
}

unsafe impl Send for DeviceState {}
unsafe impl Sync for DeviceState {}

// Use AtomicPtr instead of static mut to avoid Rust 2024 static-mut-refs error.
static DEVICE_STATE_PTR: AtomicPtr<DeviceState> = AtomicPtr::new(core::ptr::null_mut());

struct RustGuard;

impl kernel::Module for RustGuard {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("rustguard: initializing\n");

        // Allocate state on the heap via kernel allocator.
        let state = DeviceState {
            net_dev: core::ptr::null_mut(),
            udp_sock: core::ptr::null_mut(),
            peer: None,
        };

        // Allocate state on the kernel heap.
        let state_box = KBox::new(state, GFP_KERNEL)?;
        let state_raw = KBox::into_raw(state_box);

        DEVICE_STATE_PTR.store(state_raw, Ordering::Release);
        let state_void = state_raw as VoidPtr;

        // Create the net_device.
        let dev = unsafe { wg_create_device(state_void) };
        if dev.is_null() || is_err_ptr(dev) {
            pr_err!("rustguard: failed to create net device\n");
            unsafe { cleanup_state(state_raw) };
            return Err(ENOMEM);
        }
        unsafe { (*state_raw).net_dev = dev };

        // Create UDP socket on port 51820.
        let sock = unsafe { wg_socket_create(51820, state_void) };
        if sock.is_null() || is_err_ptr(sock) {
            pr_err!("rustguard: failed to create UDP socket\n");
            unsafe {
                wg_destroy_device(dev);
                cleanup_state(state_raw);
            };
            return Err(ENOMEM);
        }
        unsafe { (*state_raw).udp_sock = sock };

        // Configure test peer from module params.
        let pip = unsafe { wg_param_peer_ip() };
        let pport = unsafe { wg_param_peer_port() } as u16;
        let role = unsafe { wg_param_role() };

        if pip != 0 {
            // Hardcoded test keys — same on both sides, direction swapped by role.
            let key_a: [u8; 32] = [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            ];
            let key_b: [u8; 32] = [
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
            ];

            let (ks, kr) = if role == 0 { (key_a, key_b) } else { (key_b, key_a) };

            let peer = Peer {
                endpoint_ip: pip,
                endpoint_port: pport,
                key_send: ks,
                key_recv: kr,
                their_index: 42,
                send_counter: AtomicU64::new(0),
            };

            unsafe { (*state_raw).peer = Some(peer) };
            pr_info!("rustguard: peer configured at {:x}:{} role={}\n", pip, pport, role);
        }

        pr_info!("rustguard: wg0 created, listening on UDP 51820\n");
        Ok(RustGuard)
    }
}

impl Drop for RustGuard {
    fn drop(&mut self) {
        let state_raw = DEVICE_STATE_PTR.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !state_raw.is_null() {
            // SAFETY: state_raw was allocated by us in init and is valid.
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
        pr_info!("rustguard: unloaded\n");
    }
}

unsafe fn cleanup_state(ptr: *mut DeviceState) {
    // SAFETY: ptr was obtained from KBox::into_raw in init.
    unsafe { drop(KBox::from_raw(ptr)) };
    DEVICE_STATE_PTR.store(core::ptr::null_mut(), Ordering::Release);
}

// ── TX path ───────────────────────────────────────────────────────────

/// TX callback from C shim — encrypt and send via UDP.
#[no_mangle]
pub extern "C" fn rustguard_xmit(skb: VoidPtr, priv_: VoidPtr) -> i32 {
    // SAFETY: priv_ is a valid DeviceState pointer stored by wg_create_device.
    // skb is a valid sk_buff from the kernel.
    unsafe { do_xmit(skb, priv_) }
}

unsafe fn do_xmit(skb: VoidPtr, priv_: VoidPtr) -> i32 {
    unsafe {
        let state = &*(priv_ as *const DeviceState);

        let peer = match &state.peer {
            Some(p) => p,
            None => {
                wg_kfree_skb(skb);
                return 0;
            }
        };

        let mut data_ptr: *mut u8 = core::ptr::null_mut();
        let mut data_len: u32 = 0;
        wg_skb_data(skb, &mut data_ptr, &mut data_len);

        if data_ptr.is_null() || data_len == 0 {
            wg_kfree_skb(skb);
            return 0;
        }

        let total_len = WG_HEADER_SIZE + data_len as usize + AEAD_TAG_SIZE;
        let mut buf = [0u8; 2048];
        if total_len > buf.len() {
            wg_kfree_skb(skb);
            return 0;
        }

        let counter = peer.send_counter.fetch_add(1, Ordering::Relaxed);
        buf[0..4].copy_from_slice(&MSG_TRANSPORT.to_le_bytes());
        buf[4..8].copy_from_slice(&peer.their_index.to_le_bytes());
        buf[8..16].copy_from_slice(&counter.to_le_bytes());

        let plaintext = core::slice::from_raw_parts(data_ptr, data_len as usize);
        let ret = wg_chacha20poly1305_encrypt(
            peer.key_send.as_ptr(),
            counter,
            plaintext.as_ptr(),
            data_len,
            core::ptr::null(), 0,
            buf.as_mut_ptr().add(WG_HEADER_SIZE),
        );

        wg_kfree_skb(skb);

        if ret != 0 {
            return 0;
        }

        wg_socket_send(
            state.udp_sock,
            buf.as_ptr(),
            total_len as u32,
            peer.endpoint_ip,
            peer.endpoint_port,
        );

        wg_tx_stats(state.net_dev, data_len);

        0
    }
}

// ── RX path ───────────────────────────────────────────────────────────

/// RX callback from C shim — decrypt and inject into kernel stack.
#[no_mangle]
pub extern "C" fn rustguard_rx(skb: VoidPtr, priv_: VoidPtr) -> i32 {
    // SAFETY: same as xmit — valid pointers from C.
    unsafe { do_rx(skb, priv_) }
}

unsafe fn do_rx(skb: VoidPtr, priv_: VoidPtr) -> i32 {
    unsafe {
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

        let msg_type = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        if msg_type != MSG_TRANSPORT {
            wg_kfree_skb(skb);
            return 0;
        }

        let counter = u64::from_le_bytes([
            pkt[8], pkt[9], pkt[10], pkt[11],
            pkt[12], pkt[13], pkt[14], pkt[15],
        ]);

        let encrypted = &pkt[WG_HEADER_SIZE..];
        let encrypted_len = encrypted.len();

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

        wg_kfree_skb(skb);

        if ret != 0 {
            return 0;
        }

        let plaintext_len = encrypted_len - AEAD_TAG_SIZE;

        let new_skb = wg_alloc_skb(plaintext_len as u32);
        if new_skb.is_null() {
            return 0;
        }

        let dest = skb_put(new_skb, plaintext_len as u32);
        core::ptr::copy_nonoverlapping(plaintext_buf.as_ptr(), dest, plaintext_len);

        wg_net_rx(state.net_dev, new_skb);

        0
    }
}

/// Device teardown callback from C shim.
#[no_mangle]
pub extern "C" fn rustguard_dev_uninit(_priv: VoidPtr) {}

fn is_err_ptr(ptr: VoidPtr) -> bool {
    let val = ptr as isize;
    val >= -4095 && val < 0
}
