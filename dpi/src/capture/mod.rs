//! Platform-specific packet capture and re-injection.
//!
//! Each backend exposes the same `PacketHandle` type and its two core methods:
//!   - `recv() -> Result<OwnedPacket>`  — block until one packet arrives
//!   - `send(&[u8]) -> Result<()>`       — inject a raw packet
//!
//! On Linux  : nfqueue (kernel queues intercepted packets to userspace)
//! On macOS  : libpcap / BPF (read-only capture; injection via raw socket)
//! On Windows: WinDivert (kernel driver intercepts and re-injects)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("capture init error: {0}")]
    Init(String),
    #[error("recv error: {0}")]
    Recv(String),
    #[error("send error: {0}")]
    Send(String),
}

/// A raw intercepted packet with mutable access to the bytes.
#[derive(Debug)]
pub struct OwnedPacket {
    pub data: Vec<u8>,
    /// Opaque handle used by the backend to accept/drop/reinject.
    #[allow(dead_code)]
    pub(crate) id: u64,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::PacketHandle;
#[cfg(target_os = "macos")]
pub use macos::PacketHandle;
#[cfg(target_os = "windows")]
pub use windows::PacketHandle;
