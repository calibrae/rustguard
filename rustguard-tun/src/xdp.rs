//! AF_XDP zero-copy UDP I/O for Linux.
//!
//! Replaces the standard UDP socket for receiving/sending WireGuard
//! encrypted packets. The plaintext side still uses TUN.
//!
//! Architecture:
//!   NIC -> XDP BPF filter (UDP:51820) -> AF_XDP socket -> decrypt -> TUN
//!   TUN -> encrypt -> AF_XDP TX ring -> NIC
//!
//! The unsafe is contained in this module. The ring buffer protocol is
//! lock-free (atomic producer/consumer indices on shared mmap'd memory).

#![cfg(target_os = "linux")]

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};

// ── Constants ───────────────────────────────────────────────────────

const AF_XDP: i32 = 44;
const SOL_XDP: i32 = 283;

const XDP_UMEM_REG: i32 = 4;
const XDP_UMEM_FILL_RING: i32 = 5;
const XDP_UMEM_COMPLETION_RING: i32 = 6;
const XDP_RX_RING: i32 = 2;
const XDP_TX_RING: i32 = 3;
const XDP_MMAP_OFFSETS: i32 = 1;

const XDP_PGOFF_RX_RING: i64 = 0;
const XDP_PGOFF_TX_RING: i64 = 0x0_8000_0000;
const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x1_0000_0000;
const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x1_8000_0000;

const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;
const XDP_RING_NEED_WAKEUP: u32 = 1;

// ── Struct layouts (matching kernel uapi) ───────────────────────────

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrXdp {
    family: u16,
    flags: u16,
    ifindex: u32,
    queue_id: u32,
    shared_umem_fd: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

#[repr(C)]
#[derive(Default)]
struct XdpRingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct XdpMmapOffsets {
    rx: XdpRingOffset,
    tx: XdpRingOffset,
    fr: XdpRingOffset,
    cr: XdpRingOffset,
}

// ── Ring buffer ─────────────────────────────────────────────────────

/// A single-producer/single-consumer ring over mmap'd memory.
struct Ring {
    producer: *const AtomicU32,
    consumer: *const AtomicU32,
    flags: *const AtomicU32,
    descs: *mut u8, // Either *mut XdpDesc or *mut u64 depending on ring type.
    mask: u32,
}

// Safety: Ring pointers come from mmap and are valid for the socket lifetime.
unsafe impl Send for Ring {}
unsafe impl Sync for Ring {}

impl Ring {
    fn producer(&self) -> u32 {
        unsafe { (*self.producer).load(Ordering::Acquire) }
    }

    fn consumer(&self) -> u32 {
        unsafe { (*self.consumer).load(Ordering::Acquire) }
    }

    fn set_producer(&self, val: u32) {
        unsafe { (*self.producer).store(val, Ordering::Release) }
    }

    fn set_consumer(&self, val: u32) {
        unsafe { (*self.consumer).store(val, Ordering::Release) }
    }

    fn needs_wakeup(&self) -> bool {
        unsafe { (*self.flags).load(Ordering::Relaxed) & XDP_RING_NEED_WAKEUP != 0 }
    }
}

// ── XDP Socket ──────────────────────────────────────────────────────

/// Configuration for creating an XDP socket.
pub struct XdpConfig {
    pub ifname: String,
    pub queue_id: u32,
    pub frame_size: u32,
    pub num_frames: u32,
    pub ring_size: u32,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            ifname: "eth0".into(),
            queue_id: 0,
            frame_size: 4096,
            num_frames: 4096,
            ring_size: 2048,
        }
    }
}

/// An mmap'd ring region with its base pointer and size for cleanup.
struct MmapRegion {
    base: *mut u8,
    size: usize,
}

/// An AF_XDP socket with UMEM and ring buffers.
/// Provides zero-copy packet I/O for the encrypted UDP side.
pub struct XdpSocket {
    fd: i32,
    umem: *mut u8,
    umem_size: usize,
    frame_size: u32,
    rx_ring: Ring,
    tx_ring: Ring,
    fill_ring: Ring,
    comp_ring: Ring,
    ring_size: u32,
    /// Free frame indices for TX.
    free_frames: Vec<u64>,
    /// mmap'd ring regions that must be munmap'd on drop.
    ring_maps: [MmapRegion; 4],
}

// Safety: XdpSocket owns its fd and mmap regions.
unsafe impl Send for XdpSocket {}

impl XdpSocket {
    /// Create and configure an AF_XDP socket.
    ///
    /// # Safety
    /// This function uses mmap to create shared memory regions with the kernel.
    /// The returned XdpSocket must not outlive the process.
    pub fn create(config: &XdpConfig) -> io::Result<Self> {
        unsafe { Self::create_inner(config) }
    }

    unsafe fn create_inner(config: &XdpConfig) -> io::Result<Self> {
        let umem_size = (config.frame_size * config.num_frames) as usize;

        // 1. Allocate UMEM.
        let umem = libc::mmap(
            std::ptr::null_mut(),
            umem_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
            -1,
            0,
        );
        if umem == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let umem = umem as *mut u8;

        // 2. Create socket.
        let fd = libc::socket(AF_XDP, libc::SOCK_RAW, 0);
        if fd < 0 {
            libc::munmap(umem as *mut _, umem_size);
            return Err(io::Error::last_os_error());
        }

        // 3. Register UMEM.
        let reg = XdpUmemReg {
            addr: umem as u64,
            len: umem_size as u64,
            chunk_size: config.frame_size,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        if setsockopt_raw(fd, SOL_XDP, XDP_UMEM_REG, &reg) < 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            libc::munmap(umem as *mut _, umem_size);
            return Err(err);
        }

        // 4. Set ring sizes — check each return value.
        let rs = config.ring_size as i32;
        for &optname in &[XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING, XDP_RX_RING, XDP_TX_RING] {
            if setsockopt_raw(fd, SOL_XDP, optname, &rs) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                libc::munmap(umem as *mut _, umem_size);
                return Err(err);
            }
        }

        // 5. Query mmap offsets.
        let mut offsets = XdpMmapOffsets::default();
        let mut optlen = std::mem::size_of::<XdpMmapOffsets>() as u32;
        if libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            &mut offsets as *mut _ as *mut _,
            &mut optlen,
        ) < 0
        {
            let err = io::Error::last_os_error();
            libc::close(fd);
            libc::munmap(umem as *mut _, umem_size);
            return Err(err);
        }

        // 6. mmap rings.
        let rx_map = mmap_ring(fd, &offsets.rx, config.ring_size, XDP_PGOFF_RX_RING, std::mem::size_of::<XdpDesc>())?;
        let tx_map = mmap_ring(fd, &offsets.tx, config.ring_size, XDP_PGOFF_TX_RING, std::mem::size_of::<XdpDesc>())?;
        let fill_map = mmap_ring(fd, &offsets.fr, config.ring_size, XDP_UMEM_PGOFF_FILL_RING, 8)?;
        let comp_map = mmap_ring(fd, &offsets.cr, config.ring_size, XDP_UMEM_PGOFF_COMPLETION_RING, 8)?;

        let mask = config.ring_size - 1;
        let rx_ring = make_ring(rx_map.base, &offsets.rx, mask);
        let tx_ring = make_ring(tx_map.base, &offsets.tx, mask);
        let fill_ring = make_ring(fill_map.base, &offsets.fr, mask);
        let comp_ring = make_ring(comp_map.base, &offsets.cr, mask);

        // 7. Pre-populate fill ring (first half of frames for RX).
        let rx_frames = config.num_frames / 2;
        let mut prod = fill_ring.producer();
        for i in 0..rx_frames {
            let addr_ptr = fill_ring.descs.add(((prod & mask) as usize) * 8) as *mut u64;
            *addr_ptr = (i * config.frame_size) as u64;
            prod += 1;
        }
        fill_ring.set_producer(prod);

        // Second half of frames are free for TX.
        let mut free_frames = Vec::with_capacity((config.num_frames - rx_frames) as usize);
        for i in rx_frames..config.num_frames {
            free_frames.push((i * config.frame_size) as u64);
        }

        // 8. Bind.
        let ifindex = if_nametoindex(&config.ifname)?;
        let sxdp = SockaddrXdp {
            family: AF_XDP as u16,
            flags: XDP_USE_NEED_WAKEUP,
            ifindex,
            queue_id: config.queue_id,
            shared_umem_fd: 0,
        };
        if libc::bind(fd, &sxdp as *const _ as *const _, std::mem::size_of::<SockaddrXdp>() as u32) < 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            libc::munmap(umem as *mut _, umem_size);
            return Err(err);
        }

        Ok(Self {
            fd,
            umem,
            umem_size,
            frame_size: config.frame_size,
            rx_ring,
            tx_ring,
            fill_ring,
            comp_ring,
            ring_size: config.ring_size,
            free_frames,
            ring_maps: [rx_map, tx_map, fill_map, comp_map],
        })
    }

    /// Receive packets. Returns an iterator over (frame_addr, packet_data) pairs.
    /// Caller must call `rx_release` after processing to return frames to the fill ring.
    pub fn rx_poll(&self) -> Vec<(u64, &[u8])> {
        let prod = self.rx_ring.producer();
        let cons = self.rx_ring.consumer();
        let available = prod.wrapping_sub(cons);

        let mut packets = Vec::with_capacity(available as usize);
        for i in 0..available {
            let idx = (cons.wrapping_add(i) & (self.ring_size - 1)) as usize;
            let desc = unsafe {
                &*(self.rx_ring.descs.add(idx * std::mem::size_of::<XdpDesc>()) as *const XdpDesc)
            };
            let data = unsafe {
                std::slice::from_raw_parts(
                    self.umem.add(desc.addr as usize),
                    desc.len as usize,
                )
            };
            packets.push((desc.addr, data));
        }
        packets
    }

    /// Release consumed RX frames back to the fill ring.
    pub fn rx_release(&mut self, frames: &[u64]) {
        // Update RX consumer.
        let cons = self.rx_ring.consumer().wrapping_add(frames.len() as u32);
        self.rx_ring.set_consumer(cons);

        // Add frames back to fill ring.
        let mut prod = self.fill_ring.producer();
        for &addr in frames {
            let idx = (prod & (self.ring_size - 1)) as usize;
            unsafe {
                let ptr = self.fill_ring.descs.add(idx * 8) as *mut u64;
                *ptr = addr;
            }
            prod = prod.wrapping_add(1);
        }
        self.fill_ring.set_producer(prod);
    }

    /// Send a packet via the TX ring. Returns false if no frames available
    /// or data exceeds frame size.
    pub fn tx_send(&mut self, data: &[u8]) -> bool {
        if data.len() > self.frame_size as usize {
            return false;
        }

        let Some(frame_addr) = self.free_frames.pop() else {
            return false;
        };

        // Copy data into UMEM frame.
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.umem.add(frame_addr as usize),
                data.len(),
            );
        }

        // Write TX descriptor.
        let prod = self.tx_ring.producer();
        let idx = (prod & (self.ring_size - 1)) as usize;
        unsafe {
            let desc = &mut *(self.tx_ring.descs.add(idx * std::mem::size_of::<XdpDesc>()) as *mut XdpDesc);
            desc.addr = frame_addr;
            desc.len = data.len() as u32;
            desc.options = 0;
        }
        self.tx_ring.set_producer(prod.wrapping_add(1));

        // Kick kernel if needed.
        if self.tx_ring.needs_wakeup() {
            unsafe {
                libc::sendto(self.fd, std::ptr::null(), 0, libc::MSG_DONTWAIT, std::ptr::null(), 0);
            }
        }

        true
    }

    /// Reclaim completed TX frames.
    pub fn tx_complete(&mut self) {
        let prod = self.comp_ring.producer();
        let cons = self.comp_ring.consumer();
        let done = prod.wrapping_sub(cons);

        for i in 0..done {
            let idx = (cons.wrapping_add(i) & (self.ring_size - 1)) as usize;
            let addr = unsafe { *(self.comp_ring.descs.add(idx * 8) as *const u64) };
            self.free_frames.push(addr);
        }
        self.comp_ring.set_consumer(cons.wrapping_add(done));
    }

    /// Raw file descriptor (for poll/epoll).
    pub fn fd(&self) -> i32 {
        self.fd
    }
}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
            // Unmap ring regions first, then UMEM.
            for region in &self.ring_maps {
                if !region.base.is_null() && region.size > 0 {
                    libc::munmap(region.base as *mut _, region.size);
                }
            }
            libc::munmap(self.umem as *mut _, self.umem_size);
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

unsafe fn setsockopt_raw<T>(fd: i32, level: i32, optname: i32, val: &T) -> i32 {
    libc::setsockopt(
        fd,
        level,
        optname,
        val as *const _ as *const _,
        std::mem::size_of::<T>() as u32,
    )
}

unsafe fn mmap_ring(
    fd: i32,
    off: &XdpRingOffset,
    ring_size: u32,
    pgoff: i64,
    desc_size: usize,
) -> io::Result<MmapRegion> {
    let size = off.desc as usize + (ring_size as usize) * desc_size;
    let ptr = libc::mmap(
        std::ptr::null_mut(),
        size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED | libc::MAP_POPULATE,
        fd,
        pgoff,
    );
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(MmapRegion {
        base: ptr as *mut u8,
        size,
    })
}

unsafe fn make_ring(base: *mut u8, off: &XdpRingOffset, mask: u32) -> Ring {
    Ring {
        producer: base.add(off.producer as usize) as *const AtomicU32,
        consumer: base.add(off.consumer as usize) as *const AtomicU32,
        flags: base.add(off.flags as usize) as *const AtomicU32,
        descs: base.add(off.desc as usize),
        mask,
    }
}

pub fn if_nametoindex(name: &str) -> io::Result<u32> {
    let cname = std::ffi::CString::new(name).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name")
    })?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(idx)
}
