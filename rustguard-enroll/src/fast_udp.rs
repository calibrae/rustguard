//! Batched UDP I/O using recvmmsg/sendmmsg.
//!
//! On Linux, recvmmsg/sendmmsg receive/send multiple datagrams in a
//! single syscall. This amortizes the context switch overhead across
//! a batch of packets — the biggest single-stream throughput win for
//! userspace networking.
//!
//! On macOS, falls back to regular recv_from/send_to.

use std::io;
use std::net::{SocketAddr, UdpSocket};

/// Maximum batch size for recvmmsg/sendmmsg.
pub const BATCH_SIZE: usize = 32;
/// Per-packet buffer size.
pub const PKT_BUF_SIZE: usize = 2048;

/// A batch of received packets.
pub struct RecvBatch {
    pub bufs: [[u8; PKT_BUF_SIZE]; BATCH_SIZE],
    pub lens: [usize; BATCH_SIZE],
    pub addrs: [Option<SocketAddr>; BATCH_SIZE],
    pub count: usize,
}

impl RecvBatch {
    pub fn new() -> Self {
        Self {
            bufs: [[0u8; PKT_BUF_SIZE]; BATCH_SIZE],
            lens: [0; BATCH_SIZE],
            addrs: [None; BATCH_SIZE],
            count: 0,
        }
    }
}

/// Receive a batch of packets. Returns number received (0 on timeout).
#[cfg(target_os = "linux")]
pub fn recv_batch(sock: &UdpSocket, batch: &mut RecvBatch) -> io::Result<usize> {
    use std::os::unix::io::AsRawFd;

    let fd = sock.as_raw_fd();

    let mut iovecs: [libc::iovec; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut addrs: [libc::sockaddr_storage; BATCH_SIZE] = unsafe { std::mem::zeroed() };

    for i in 0..BATCH_SIZE {
        iovecs[i].iov_base = batch.bufs[i].as_mut_ptr() as *mut _;
        iovecs[i].iov_len = PKT_BUF_SIZE;
        msgs[i].msg_hdr.msg_iov = &mut iovecs[i] as *mut _;
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut _;
        msgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
    }

    let ret = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            BATCH_SIZE as u32,
            libc::MSG_WAITFORONE as u32, // Block for at least one, then grab more non-blocking.
            std::ptr::null_mut(),
        )
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            batch.count = 0;
            return Ok(0);
        }
        return Err(err);
    }

    batch.count = ret as usize;
    for i in 0..batch.count {
        batch.lens[i] = msgs[i].msg_len as usize;
        batch.addrs[i] = sockaddr_to_socketaddr(&addrs[i]);
    }

    Ok(batch.count)
}

#[cfg(target_os = "linux")]
fn sockaddr_to_socketaddr(sa: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match sa.ss_family as i32 {
        libc::AF_INET => {
            let sin = unsafe { &*(sa as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Some(SocketAddr::from((ip, port)))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(sa as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Some(SocketAddr::from((ip, port)))
        }
        _ => None,
    }
}

/// Send a single packet. Could be extended to sendmmsg batching later.
#[cfg(target_os = "linux")]
pub fn send_packet(sock: &UdpSocket, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
    sock.send_to(buf, addr)
}

/// macOS fallback: receive one packet at a time.
#[cfg(target_os = "macos")]
pub fn recv_batch(sock: &UdpSocket, batch: &mut RecvBatch) -> io::Result<usize> {
    match sock.recv_from(&mut batch.bufs[0]) {
        Ok((n, addr)) => {
            batch.lens[0] = n;
            batch.addrs[0] = Some(addr);
            batch.count = 1;
            Ok(1)
        }
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
            batch.count = 0;
            Ok(0)
        }
        Err(e) => Err(e),
    }
}

#[cfg(target_os = "macos")]
pub fn send_packet(sock: &UdpSocket, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
    sock.send_to(buf, addr)
}
