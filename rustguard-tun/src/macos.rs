//! macOS utun implementation.
//!
//! Creates a utun device via the kernel control socket interface.
//! No third-party dependencies — just raw syscalls against the Darwin kernel.

use std::io;
use std::net::Ipv4Addr;

use crate::{Tun, TunConfig};

// ── Constants from Darwin headers ───────────────────────────────────

const AF_SYSTEM: u8 = 32;
const AF_SYS_CONTROL: u16 = 2;
const SYSPROTO_CONTROL: libc::c_int = 2;
const UTUN_OPT_IFNAME: libc::c_int = 2;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

// CTLIOCGINFO = _IOWR('N', 3, struct ctl_info) = 0xc0644e03
const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;

// Ioctl constants for interface configuration.
const SIOCSIFMTU: libc::c_ulong = 0x8020_6934;
const SIOCAIFADDR: libc::c_ulong = 0x8040_691a;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;

// ── Structs matching Darwin kernel layout ───────────────────────────

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

#[repr(C)]
struct SockaddrIn {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[repr(C)]
struct IfAliasReq {
    ifra_name: [u8; 16],
    ifra_addr: SockaddrIn,
    ifra_broadaddr: SockaddrIn,
    ifra_mask: SockaddrIn,
}

#[repr(C)]
struct IfreqMtu {
    ifr_name: [u8; 16],
    ifr_mtu: i32,
}

// ── Implementation ──────────────────────────────────────────────────

fn last_os_error() -> io::Error {
    io::Error::last_os_error()
}

fn make_sockaddr_in(addr: Ipv4Addr) -> SockaddrIn {
    SockaddrIn {
        sin_len: 16,
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: addr.octets(),
        sin_zero: [0; 8],
    }
}

pub fn create(config: &TunConfig) -> io::Result<Tun> {
    unsafe {
        // 1. Create kernel control socket.
        let fd = libc::socket(
            AF_SYSTEM as libc::c_int,
            libc::SOCK_DGRAM,
            SYSPROTO_CONTROL,
        );
        if fd < 0 {
            return Err(last_os_error());
        }

        // 2. Get the control ID for utun.
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        info.ctl_name[..UTUN_CONTROL_NAME.len()]
            .copy_from_slice(UTUN_CONTROL_NAME);

        if libc::ioctl(fd, CTLIOCGINFO, &mut info as *mut _) < 0 {
            libc::close(fd);
            return Err(last_os_error());
        }

        // 3. Connect to create the utun interface.
        // sc_unit 0 = auto-assign, sc_unit N = utun(N-1).
        let unit = match &config.name {
            Some(name) => {
                let num: u32 = name
                    .strip_prefix("utun")
                    .and_then(|n| n.parse().ok())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "name must be utunN")
                    })?;
                num + 1
            }
            None => 0,
        };

        let addr = SockaddrCtl {
            sc_len: 32,
            sc_family: AF_SYSTEM,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };

        if libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            32,
        ) < 0
        {
            libc::close(fd);
            return Err(last_os_error());
        }

        // 4. Get the assigned interface name.
        let mut name_buf = [0u8; 16];
        let mut name_len: libc::socklen_t = 16;
        if libc::getsockopt(
            fd,
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name_buf.as_mut_ptr() as *mut _,
            &mut name_len,
        ) < 0
        {
            libc::close(fd);
            return Err(last_os_error());
        }

        if name_len < 2 {
            libc::close(fd);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty interface name"));
        }

        let name = std::str::from_utf8(&name_buf[..name_len as usize - 1])
            .map_err(|e| { libc::close(fd); io::Error::new(io::ErrorKind::InvalidData, format!("invalid interface name: {e}")) })?
            .to_string();

        // 5. Configure the interface address.
        if let Err(e) = configure_address(&name, config) {
            libc::close(fd);
            return Err(e);
        }

        // 6. Set MTU.
        if let Err(e) = set_mtu(&name, config.mtu) {
            libc::close(fd);
            return Err(e);
        }

        Ok(Tun { fd, name })
    }
}

fn configure_address(ifname: &str, config: &TunConfig) -> io::Result<()> {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(last_os_error());
        }

        let mut req = IfAliasReq {
            ifra_name: [0; 16],
            ifra_addr: make_sockaddr_in(config.address),
            ifra_broadaddr: make_sockaddr_in(config.destination),
            ifra_mask: make_sockaddr_in(config.netmask),
        };
        let name_bytes = ifname.as_bytes();
        req.ifra_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let ret = libc::ioctl(sock, SIOCAIFADDR, &req as *const _);
        libc::close(sock);

        if ret < 0 {
            return Err(last_os_error());
        }
        Ok(())
    }
}

fn set_mtu(ifname: &str, mtu: u16) -> io::Result<()> {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(last_os_error());
        }

        let mut req = IfreqMtu {
            ifr_name: [0; 16],
            ifr_mtu: mtu as i32,
        };
        let name_bytes = ifname.as_bytes();
        req.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let ret = libc::ioctl(sock, SIOCSIFMTU, &req as *const _);
        libc::close(sock);

        if ret < 0 {
            return Err(last_os_error());
        }
        Ok(())
    }
}

/// Read an IP packet from the utun fd, stripping the 4-byte AF header.
pub fn read(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    // utun prepends 4 bytes: [0, 0, 0, AF]. We read into a temporary
    // buffer then copy just the IP packet.
    let mut readbuf = vec![0u8; buf.len() + 4];
    let n = unsafe { libc::read(fd, readbuf.as_mut_ptr() as *mut _, readbuf.len()) };
    if n < 0 {
        return Err(last_os_error());
    }
    let n = n as usize;
    if n < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet too short — missing AF header",
        ));
    }
    let payload_len = n - 4;
    buf[..payload_len].copy_from_slice(&readbuf[4..n]);
    Ok(payload_len)
}

/// Write an IP packet to the utun fd, prepending the 4-byte AF header.
pub fn write(fd: i32, packet: &[u8]) -> io::Result<usize> {
    if packet.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty packet",
        ));
    }

    // Determine address family from IP version nibble.
    let af = match packet[0] >> 4 {
        4 => AF_INET,
        6 => AF_INET6,
        v => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown IP version: {v}"),
            ))
        }
    };

    let mut writebuf = Vec::with_capacity(packet.len() + 4);
    writebuf.extend_from_slice(&[0, 0, 0, af]);
    writebuf.extend_from_slice(packet);

    let n = unsafe { libc::write(fd, writebuf.as_ptr() as *const _, writebuf.len()) };
    if n < 0 {
        return Err(last_os_error());
    }
    // Return the number of IP payload bytes written (excluding our header).
    Ok((n as usize).saturating_sub(4))
}
