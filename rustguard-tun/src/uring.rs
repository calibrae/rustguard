//! io_uring-backed TUN I/O engine for Linux.
//!
//! Replaces blocking read()/write() on TUN fds with batched async I/O.
//! One syscall (io_uring_enter) services multiple packet reads/writes,
//! reducing per-packet context switch overhead.
//!
//! Architecture:
//!   Pre-register a fixed buffer pool (256 slots × 2KB each).
//!   Pre-fill the SQ with ReadFixed SQEs → TUN fd.
//!   On completion: decrypt packet, push WriteFixed SQE.
//!   One io_uring_enter() per batch instead of per packet.

#![cfg(target_os = "linux")]

use io_uring::{opcode, types, IoUring};
use std::io;

/// Number of buffer slots in the pool.
const NUM_BUFS: usize = 256;
/// Size of each buffer slot (MTU + headroom).
const BUF_SIZE: usize = 2048;
/// io_uring ring size (SQ entries).
const RING_ENTRIES: u32 = 256;

/// A pre-allocated buffer pool for io_uring fixed buffer I/O.
pub struct BufferPool {
    /// Contiguous allocation: NUM_BUFS × BUF_SIZE bytes.
    data: Vec<u8>,
    /// Which slots are currently owned by io_uring (in-flight).
    in_flight: [bool; NUM_BUFS],
}

impl BufferPool {
    fn new() -> Self {
        Self {
            data: vec![0u8; NUM_BUFS * BUF_SIZE],
            in_flight: [false; NUM_BUFS],
        }
    }

    /// Get a mutable reference to buffer slot `idx`.
    pub fn slot_mut(&mut self, idx: usize) -> &mut [u8] {
        let start = idx * BUF_SIZE;
        &mut self.data[start..start + BUF_SIZE]
    }

    /// Get a reference to buffer slot `idx`.
    pub fn slot(&self, idx: usize) -> &[u8] {
        let start = idx * BUF_SIZE;
        &self.data[start..start + BUF_SIZE]
    }

    /// Pointer to slot start (for io_uring SQEs).
    fn slot_ptr(&self, idx: usize) -> *mut u8 {
        unsafe { self.data.as_ptr().add(idx * BUF_SIZE) as *mut u8 }
    }

    /// Allocate a free slot. Returns None if all in-flight.
    pub fn alloc(&mut self) -> Option<usize> {
        for i in 0..NUM_BUFS {
            if !self.in_flight[i] {
                self.in_flight[i] = true;
                return Some(i);
            }
        }
        None
    }

    /// Release a slot back to the pool.
    pub fn free(&mut self, idx: usize) {
        self.in_flight[idx] = false;
    }

    /// Build iovecs for io_uring buffer registration.
    fn iovecs(&self) -> Vec<libc::iovec> {
        (0..NUM_BUFS)
            .map(|i| libc::iovec {
                iov_base: self.slot_ptr(i) as *mut _,
                iov_len: BUF_SIZE,
            })
            .collect()
    }
}

/// Completion event from io_uring.
pub struct Completion {
    /// Buffer slot index.
    pub buf_idx: usize,
    /// Whether this was a read (true) or write (false).
    pub is_read: bool,
    /// Bytes transferred, or negative errno.
    pub result: i32,
}

/// io_uring TUN I/O engine.
pub struct UringTun {
    ring: IoUring,
    pub bufs: BufferPool,
    tun_fd: i32,
    /// Number of read SQEs currently submitted and in-flight.
    pending_reads: usize,
}

// user_data encoding: bit 63 = is_read, bits 0-31 = buf_idx.
const READ_FLAG: u64 = 1 << 63;

impl UringTun {
    /// Create an io_uring TUN engine for the given TUN file descriptor.
    pub fn new(tun_fd: i32) -> io::Result<Self> {
        let ring = IoUring::new(RING_ENTRIES)?;
        let mut bufs = BufferPool::new();

        // Register fixed buffers.
        let iovecs = bufs.iovecs();
        unsafe {
            ring.submitter().register_buffers(&iovecs)?;
        }

        let mut engine = Self {
            ring,
            bufs,
            tun_fd,
            pending_reads: 0,
        };

        // Pre-fill with read SQEs to keep the TUN fd busy.
        engine.fill_reads(NUM_BUFS / 2)?;

        Ok(engine)
    }

    /// Submit read SQEs to fill available buffer slots.
    fn fill_reads(&mut self, count: usize) -> io::Result<usize> {
        let mut submitted = 0;
        for _ in 0..count {
            let Some(idx) = self.bufs.alloc() else { break };

            let sqe = opcode::ReadFixed::new(
                types::Fd(self.tun_fd),
                self.bufs.slot_ptr(idx),
                BUF_SIZE as u32,
                idx as u16,
            )
            .build()
            .user_data(READ_FLAG | idx as u64);

            unsafe {
                if self.ring.submission().push(&sqe).is_err() {
                    self.bufs.free(idx);
                    break;
                }
            }
            self.pending_reads += 1;
            submitted += 1;
        }
        Ok(submitted)
    }

    /// Submit a write SQE to send a decrypted packet to the TUN.
    /// The caller must have written the packet data into `bufs.slot_mut(buf_idx)`.
    pub fn submit_write(&mut self, buf_idx: usize, len: usize) -> io::Result<()> {
        let sqe = opcode::WriteFixed::new(
            types::Fd(self.tun_fd),
            self.bufs.slot_ptr(buf_idx),
            len as u32,
            buf_idx as u16,
        )
        .build()
        .user_data(buf_idx as u64); // No READ_FLAG = write.

        unsafe {
            self.ring
                .submission()
                .push(&sqe)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "SQ full"))?;
        }
        Ok(())
    }

    /// Submit all pending SQEs and wait for at least `min_complete` completions.
    /// Returns completed events.
    pub fn submit_and_wait(&mut self, min_complete: usize) -> io::Result<Vec<Completion>> {
        self.ring.submit_and_wait(min_complete)?;

        let mut completions = Vec::new();
        let cq = self.ring.completion();
        for cqe in cq {
            let user_data = cqe.user_data();
            let is_read = user_data & READ_FLAG != 0;
            let buf_idx = (user_data & 0xFFFF_FFFF) as usize;
            let result = cqe.result();

            if is_read {
                self.pending_reads -= 1;
            }

            completions.push(Completion {
                buf_idx,
                is_read,
                result,
            });
        }

        // Refill reads to keep the pipeline saturated.
        let to_fill = (NUM_BUFS / 2).saturating_sub(self.pending_reads);
        if to_fill > 0 {
            self.fill_reads(to_fill)?;
        }

        Ok(completions)
    }

    /// Non-blocking: submit pending SQEs and harvest any available completions.
    pub fn poll(&mut self) -> io::Result<Vec<Completion>> {
        self.ring.submit()?;

        let mut completions = Vec::new();
        let cq = self.ring.completion();
        for cqe in cq {
            let user_data = cqe.user_data();
            let is_read = user_data & READ_FLAG != 0;
            let buf_idx = (user_data & 0xFFFF_FFFF) as usize;
            let result = cqe.result();

            if is_read {
                self.pending_reads -= 1;
            }

            completions.push(Completion {
                buf_idx,
                is_read,
                result,
            });
        }

        let to_fill = (NUM_BUFS / 2).saturating_sub(self.pending_reads);
        if to_fill > 0 {
            self.fill_reads(to_fill)?;
        }

        Ok(completions)
    }
}
