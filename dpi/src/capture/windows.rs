//! Windows packet interception via WinDivert.
//!
//! WinDivert is a kernel-mode driver that intercepts network packets before
//! they are delivered, allowing userspace to inspect, modify, and re-inject them.
//! Requires the WinDivert driver to be installed (ships with Flint installer).

use windivert::WinDivert;
use windivert::layer::NetworkLayer;

use super::{CaptureError, OwnedPacket};

pub struct PacketHandle {
    wd: WinDivert<NetworkLayer>,
}

impl PacketHandle {
    /// Open a WinDivert handle with `filter` (e.g. "tcp.DstPort == 443").
    /// `priority` controls processing order when multiple handles are open.
    pub fn open(filter: &str, priority: i16) -> Result<Self, CaptureError> {
        let wd = WinDivert::network(filter, priority, Default::default())
            .map_err(|e| CaptureError::Init(e.to_string()))?;
        Ok(PacketHandle { wd })
    }

    /// Block until the next matching packet is intercepted.
    pub fn recv(&mut self) -> Result<OwnedPacket, CaptureError> {
        let mut buf = vec![0u8; 65535];
        let (packet, _addr) = self.wd
            .recv(Some(&mut buf))
            .map_err(|e| CaptureError::Recv(e.to_string()))?;

        Ok(OwnedPacket {
            data: packet.to_vec(),
            id:   0,
        })
    }

    /// Re-inject a (possibly modified) packet back into the network stack.
    pub fn send(&self, packet: &[u8]) -> Result<(), CaptureError> {
        self.wd
            .send(packet)
            .map_err(|e| CaptureError::Send(e.to_string()))?;
        Ok(())
    }
}
