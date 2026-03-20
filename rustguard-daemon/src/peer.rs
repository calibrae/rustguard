//! Peer state management.
//!
//! Each peer has a public key, optional endpoint, allowed IPs,
//! and an active transport session (after handshake).

use std::net::SocketAddr;
use std::time::Duration;

use rustguard_core::session::TransportSession;
use rustguard_core::timers::SessionTimers;
use rustguard_crypto::PublicKey;

use crate::config::{CidrAddr, PeerConfig};

/// Runtime state for a WireGuard peer.
pub struct Peer {
    pub public_key: PublicKey,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<CidrAddr>,
    pub persistent_keepalive: Option<Duration>,
    /// Active transport session, set after successful handshake.
    pub session: Option<TransportSession>,
    /// Timer state for session lifecycle.
    pub timers: SessionTimers,
}

impl Peer {
    pub fn from_config(config: &PeerConfig) -> Self {
        Self {
            public_key: PublicKey::from_bytes(config.public_key),
            endpoint: config.endpoint,
            allowed_ips: config.allowed_ips.clone(),
            persistent_keepalive: config
                .persistent_keepalive
                .map(|s| Duration::from_secs(s as u64)),
            session: None,
            timers: SessionTimers::new(),
        }
    }

    /// Check if this peer is allowed to send/receive packets for the given IP.
    pub fn allows_ip(&self, ip: std::net::Ipv4Addr) -> bool {
        self.allowed_ips.iter().any(|cidr| cidr.contains(ip))
    }

    /// Whether this peer has a completed, non-expired handshake.
    pub fn has_active_session(&self) -> bool {
        self.session.is_some()
            && !self.timers.is_expired(
                self.session
                    .as_ref()
                    .map(|s| s.send_counter())
                    .unwrap_or(0),
            )
    }
}
