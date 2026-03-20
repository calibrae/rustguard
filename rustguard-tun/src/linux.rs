//! Linux TUN implementation via /dev/net/tun.
//!
//! Uses IFF_TUN | IFF_NO_PI — raw IP packets, no protocol info header.
//! Unlike macOS utun, Linux gives us clean IP frames with no prefix bytes.

use std::io;
use std::net::Ipv4Addr;

use crate::{Tun, TunConfig};

// ioctl request codes — Linux ioctl takes c_int, not c_ulong.
const TUNSETIFF: libc::c_int = 0x400454ca_u32 as libc::c_int;
const SIOCSIFADDR: libc::c_int = 0x8916;
const SIOCSIFDSTADDR: libc::c_int = 0x8918;
const SIOCSIFNETMASK: libc::c_int = 0x891c;
const SIOCSIFMTU: libc::c_int = 0x8922;
const SIOCSIFFLAGS: libc::c_int = 0x8914;
const SIOCGIFFLAGS: libc::c_int = 0x8913;

// TUN flags.
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

// Interface flags.
const IFF_UP: libc::c_short = 0x1;

const IFNAMSIZ: usize = 16;

// ── Structs matching Linux kernel layout ────────────────────────────

#[repr(C)]
struct IfreqFlags {
    ifr_name: [u8; IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22], // union padding to 32 bytes
}

#[repr(C)]
struct IfreqAddr {
    ifr_name: [u8; IFNAMSIZ],
    ifr_addr: libc::sockaddr_in,
}

#[repr(C)]
struct IfreqMtu {
    ifr_name: [u8; IFNAMSIZ],
    ifr_mtu: libc::c_int,
    _pad: [u8; 20], // ifreq union is 24 bytes, c_int is 4
}

fn last_os_error() -> io::Error {
    io::Error::last_os_error()
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

fn set_name(buf: &mut [u8; IFNAMSIZ], name: &str) {
    let bytes = name.as_bytes();
    let len = bytes.len().min(IFNAMSIZ - 1);
    buf[..len].copy_from_slice(&bytes[..len]);
}

pub fn create(config: &TunConfig) -> io::Result<Tun> {
    unsafe {
        // 1. Open /dev/net/tun.
        let fd = libc::open(
            b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR,
        );
        if fd < 0 {
            return Err(last_os_error());
        }

        // 2. Set up the interface with TUNSETIFF.
        let mut ifr = IfreqFlags {
            ifr_name: [0; IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };

        if let Some(name) = &config.name {
            set_name(&mut ifr.ifr_name, name);
        }

        if libc::ioctl(fd, TUNSETIFF, &mut ifr as *mut _) < 0 {
            libc::close(fd);
            return Err(last_os_error());
        }

        // Extract the assigned name.
        let name_end = ifr
            .ifr_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(IFNAMSIZ);
        let name = std::str::from_utf8(&ifr.ifr_name[..name_end])
            .map_err(|e| { libc::close(fd); io::Error::new(io::ErrorKind::InvalidData, format!("invalid interface name: {e}")) })?
            .to_string();

        // 3. Configure addresses and MTU via a separate socket.
        if let Err(e) = configure_interface(&name, config) {
            libc::close(fd);
            return Err(e);
        }

        Ok(Tun { fd, name })
    }
}

fn configure_interface(ifname: &str, config: &TunConfig) -> io::Result<()> {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(last_os_error());
        }

        // Set local address.
        let mut req = IfreqAddr {
            ifr_name: [0; IFNAMSIZ],
            ifr_addr: make_sockaddr_in(config.address),
        };
        set_name(&mut req.ifr_name, ifname);
        if libc::ioctl(sock, SIOCSIFADDR, &req as *const _) < 0 {
            libc::close(sock);
            return Err(last_os_error());
        }

        // Set destination (peer) address.
        req.ifr_addr = make_sockaddr_in(config.destination);
        if libc::ioctl(sock, SIOCSIFDSTADDR, &req as *const _) < 0 {
            libc::close(sock);
            return Err(last_os_error());
        }

        // Set netmask.
        req.ifr_addr = make_sockaddr_in(config.netmask);
        if libc::ioctl(sock, SIOCSIFNETMASK, &req as *const _) < 0 {
            libc::close(sock);
            return Err(last_os_error());
        }

        // Set MTU.
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
            libc::close(sock);
            return Err(last_os_error());
        }

        // Bring the interface up.
        let mut flags_req = IfreqFlags {
            ifr_name: [0; IFNAMSIZ],
            ifr_flags: 0,
            _pad: [0; 22],
        };
        set_name(&mut flags_req.ifr_name, ifname);

        // Get current flags.
        if libc::ioctl(sock, SIOCGIFFLAGS, &mut flags_req as *mut _) < 0 {
            libc::close(sock);
            return Err(last_os_error());
        }

        // Set IFF_UP.
        flags_req.ifr_flags |= IFF_UP;
        if libc::ioctl(sock, SIOCSIFFLAGS, &flags_req as *const _) < 0 {
            libc::close(sock);
            return Err(last_os_error());
        }

        libc::close(sock);
        Ok(())
    }
}

/// Read a raw IP packet from the TUN device.
/// Linux with IFF_NO_PI gives us clean IP frames — no header to strip.
pub fn read(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
    if n < 0 {
        return Err(last_os_error());
    }
    Ok(n as usize)
}

/// Write a raw IP packet to the TUN device.
/// No header needed — IFF_NO_PI means we write the IP packet directly.
pub fn write(fd: i32, packet: &[u8]) -> io::Result<usize> {
    if packet.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty packet"));
    }
    let n = unsafe { libc::write(fd, packet.as_ptr() as *const _, packet.len()) };
    if n < 0 {
        return Err(last_os_error());
    }
    Ok(n as usize)
}
