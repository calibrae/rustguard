use std::io;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub mod linux_mq;

#[cfg(target_os = "linux")]
pub mod uring;

#[cfg(target_os = "linux")]
pub mod xdp;

#[cfg(target_os = "linux")]
pub mod bpf_loader;

/// A TUN device that can read and write IP packets.
///
/// On macOS this is a utun interface created via the kernel control socket.
/// On Linux this is /dev/net/tun with IFF_TUN | IFF_NO_PI.
pub struct Tun {
    /// Raw file descriptor for the TUN device.
    fd: i32,
    /// Interface name (e.g. "utun3" on macOS, "tun0" on Linux).
    name: String,
}

/// Configuration for creating a TUN device.
pub struct TunConfig {
    /// Desired interface name/number. None = let the OS pick.
    pub name: Option<String>,
    /// MTU for the interface. Default: 1420 (WireGuard standard).
    pub mtu: u16,
    /// Local address to assign (e.g. "10.0.0.1").
    pub address: std::net::Ipv4Addr,
    /// Peer/destination address for the point-to-point link.
    pub destination: std::net::Ipv4Addr,
    /// Netmask (e.g. "255.255.255.0").
    pub netmask: std::net::Ipv4Addr,
}

impl Tun {
    /// Create and configure a new TUN device.
    pub fn create(config: &TunConfig) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        return macos::create(config);

        #[cfg(target_os = "linux")]
        return linux::create(config);

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        return Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform"));
    }

    /// Raw file descriptor. Needed for io_uring and AF_XDP integration.
    pub fn raw_fd(&self) -> i32 {
        self.fd
    }

    /// Interface name (e.g. "utun3").
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read an IP packet from the TUN device.
    ///
    /// Strips the platform-specific header (4-byte AF on macOS, nothing on Linux).
    /// Returns the number of bytes read into `buf`.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(target_os = "macos")]
        return macos::read(self.fd, buf);

        #[cfg(target_os = "linux")]
        return linux::read(self.fd, buf);

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        return Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform"));
    }

    /// Write an IP packet to the TUN device.
    ///
    /// Prepends the platform-specific header automatically (macOS only).
    pub fn write(&self, packet: &[u8]) -> io::Result<usize> {
        #[cfg(target_os = "macos")]
        return macos::write(self.fd, packet);

        #[cfg(target_os = "linux")]
        return linux::write(self.fd, packet);

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        return Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform"));
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
