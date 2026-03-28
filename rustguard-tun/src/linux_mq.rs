//! Multi-queue TUN for Linux.
//!
//! Opens multiple file descriptors to the same TUN device using IFF_MULTI_QUEUE.
//! Each fd can be read/written independently by a separate thread, spreading
//! the TUN I/O load across cores. This is the same technique wireguard-go uses.
//!
//! The kernel distributes incoming packets across queues via flow hashing.
//! Outgoing packets can be written to any queue.

#![cfg(target_os = "linux")]

use std::io;
use std::net::Ipv4Addr;

use crate::TunConfig;

// Same constants as linux.rs.
const TUNSETIFF: libc::c_int = 0x400454ca_u32 as libc::c_int;
const SIOCSIFADDR: libc::c_int = 0x8916;
const SIOCSIFDSTADDR: libc::c_int = 0x8918;
const SIOCSIFNETMASK: libc::c_int = 0x891c;
const SIOCSIFMTU: libc::c_int = 0x8922;
const SIOCSIFFLAGS: libc::c_int = 0x8914;
const SIOCGIFFLAGS: libc::c_int = 0x8913;

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;

const IFF_UP: libc::c_short = 0x1;
const IFNAMSIZ: usize = 16;

#[repr(C)]
struct IfreqFlags {
    ifr_name: [u8; IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

#[repr(C)]
struct IfreqAddr {
    ifr_name: [u8; IFNAMSIZ],
    ifr_addr: libc::sockaddr_in,
    _pad: [u8; 8], // Kernel ifreq is 40 bytes on 64-bit; sockaddr_in is 16, name is 16, pad to 40.
}

#[repr(C)]
struct IfreqMtu {
    ifr_name: [u8; IFNAMSIZ],
    ifr_mtu: libc::c_int,
    _pad: [u8; 20],
}

fn set_name(buf: &mut [u8; IFNAMSIZ], name: &str) {
    let bytes = name.as_bytes();
    let len = bytes.len().min(IFNAMSIZ - 1);
    buf[..len].copy_from_slice(&bytes[..len]);
}

fn make_sockaddr_in(addr: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.octets()),
        },
        sin_zero: [0; 8],
    }
}

fn close_and_error(fd: i32) -> io::Error {
    let err = io::Error::last_os_error();
    unsafe { libc::close(fd) };
    err
}

/// A multi-queue TUN device with N file descriptors.
pub struct MultiQueueTun {
    fds: Vec<i32>,
    name: String,
    num_queues: usize,
}

impl MultiQueueTun {
    /// Create a multi-queue TUN device with `num_queues` queues.
    pub fn create(config: &TunConfig, num_queues: usize) -> io::Result<Self> {
        let num_queues = num_queues.max(1);

        unsafe {
            // First queue: creates the device.
            let fd0 = open_tun_queue(None)?;
            let mut ifr = IfreqFlags {
                ifr_name: [0; IFNAMSIZ],
                ifr_flags: IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
                _pad: [0; 22],
            };
            if let Some(name) = &config.name {
                set_name(&mut ifr.ifr_name, name);
            }

            if libc::ioctl(fd0, TUNSETIFF, &mut ifr as *mut _) < 0 {
                return Err(close_and_error(fd0));
            }

            let name_end = ifr.ifr_name.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
            let name = std::str::from_utf8(&ifr.ifr_name[..name_end])
                .map_err(|e| {
                    libc::close(fd0);
                    io::Error::new(io::ErrorKind::InvalidData, format!("bad name: {e}"))
                })?
                .to_string();

            let mut fds = vec![fd0];

            // Additional queues: attach to existing device.
            for _ in 1..num_queues {
                let fd = match open_tun_queue(None) {
                    Ok(fd) => fd,
                    Err(e) => {
                        for &prev_fd in &fds {
                            libc::close(prev_fd);
                        }
                        return Err(e);
                    }
                };
                let mut ifr2 = IfreqFlags {
                    ifr_name: [0; IFNAMSIZ],
                    ifr_flags: IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
                    _pad: [0; 22],
                };
                set_name(&mut ifr2.ifr_name, &name);

                if libc::ioctl(fd, TUNSETIFF, &mut ifr2 as *mut _) < 0 {
                    let err = close_and_error(fd);
                    // Close all previously opened fds.
                    for &prev_fd in &fds {
                        libc::close(prev_fd);
                    }
                    return Err(err);
                }
                fds.push(fd);
            }

            // Configure the interface (address, MTU, bring up).
            if let Err(e) = configure_interface(&name, config) {
                for &fd in &fds {
                    libc::close(fd);
                }
                return Err(e);
            }

            Ok(Self {
                fds,
                name,
                num_queues,
            })
        }
    }

    /// Number of queues.
    pub fn num_queues(&self) -> usize {
        self.num_queues
    }

    /// Interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the fd for a specific queue.
    pub fn queue_fd(&self, queue: usize) -> i32 {
        self.fds[queue % self.num_queues]
    }

    /// Read a packet from a specific queue.
    pub fn read_queue(&self, queue: usize, buf: &mut [u8]) -> io::Result<usize> {
        let fd = self.queue_fd(queue);
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Write a packet to a specific queue.
    pub fn write_queue(&self, queue: usize, packet: &[u8]) -> io::Result<usize> {
        let fd = self.queue_fd(queue);
        let n = unsafe { libc::write(fd, packet.as_ptr() as *const _, packet.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

impl Drop for MultiQueueTun {
    fn drop(&mut self) {
        for &fd in &self.fds {
            unsafe { libc::close(fd) };
        }
    }
}

unsafe fn open_tun_queue(_name: Option<&str>) -> io::Result<i32> {
    let fd = libc::open(
        b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
        libc::O_RDWR | libc::O_CLOEXEC,
    );
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

unsafe fn configure_interface(ifname: &str, config: &TunConfig) -> io::Result<()> {
    let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut req = IfreqAddr {
        ifr_name: [0; IFNAMSIZ],
        ifr_addr: make_sockaddr_in(config.address),
        _pad: [0; 8],
    };
    set_name(&mut req.ifr_name, ifname);
    if libc::ioctl(sock, SIOCSIFADDR, &req as *const _) < 0 {
        return Err(close_and_error(sock));
    }

    req.ifr_addr = make_sockaddr_in(config.destination);
    if libc::ioctl(sock, SIOCSIFDSTADDR, &req as *const _) < 0 {
        return Err(close_and_error(sock));
    }

    req.ifr_addr = make_sockaddr_in(config.netmask);
    if libc::ioctl(sock, SIOCSIFNETMASK, &req as *const _) < 0 {
        return Err(close_and_error(sock));
    }

    let mtu_req = IfreqMtu {
        ifr_name: {
            let mut n = [0; IFNAMSIZ];
            set_name(&mut n, ifname);
            n
        },
        ifr_mtu: config.mtu as libc::c_int,
        _pad: [0; 20],
    };
    if libc::ioctl(sock, SIOCSIFMTU, &mtu_req as *const _) < 0 {
        return Err(close_and_error(sock));
    }

    let mut flags_req = IfreqFlags {
        ifr_name: [0; IFNAMSIZ],
        ifr_flags: 0,
        _pad: [0; 22],
    };
    set_name(&mut flags_req.ifr_name, ifname);
    if libc::ioctl(sock, SIOCGIFFLAGS, &mut flags_req as *mut _) < 0 {
        return Err(close_and_error(sock));
    }
    flags_req.ifr_flags |= IFF_UP;
    if libc::ioctl(sock, SIOCSIFFLAGS, &flags_req as *const _) < 0 {
        return Err(close_and_error(sock));
    }

    libc::close(sock);
    Ok(())
}
