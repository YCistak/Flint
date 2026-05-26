//! TTL manipulation strategy.
//!
//! Send a "decoy" copy of the TLS ClientHello with a low TTL that expires
//! before it reaches the DPI box, followed immediately by the real packet
//! with the normal TTL.
//!
//! The DPI box sees the decoy first; if it interprets TTL-expired packets as
//! valid data it will attempt to parse a garbage/overwritten first record and
//! fail to match SNI patterns.  The destination server only ever receives
//! the real packet because the decoy dies in transit.
//!
//! Effective against: stateful DPI systems in Turkey (GCAP), Russia (TSPU).

use crate::capture::CaptureError;
use crate::packet::{IpHeader, IpProto, TcpHeader};
use crate::packet::tls::parse_client_hello;
use super::Strategy;

pub struct TtlStrategy {
    /// TTL for the decoy packet — should be less than hops-to-DPI.
    /// Typical ISP DPI sits 3–7 hops away; a value of 5 works for most cases.
    pub decoy_ttl: u8,
    /// Payload to use in the decoy packet.  If `None`, the decoy carries the
    /// same bytes as the real packet (causes the DPI to re-process the same
    /// SNI, which is fine — the point is the TTL tricks it into a bad state).
    /// Alternatively, a caller may supply random noise here.
    pub decoy_payload: Option<Vec<u8>>,
}

impl Default for TtlStrategy {
    fn default() -> Self {
        TtlStrategy { decoy_ttl: 5, decoy_payload: None }
    }
}

impl Strategy for TtlStrategy {
    fn apply(&self, packet: &[u8]) -> Result<Vec<Vec<u8>>, CaptureError> {
        let ip = match IpHeader::parse(packet) {
            Ok(h) if h.proto == IpProto::Tcp => h,
            _ => return Ok(vec![packet.to_vec()]),
        };

        let tcp_buf = &packet[ip.header_len..];
        let tcp = match TcpHeader::parse(tcp_buf) {
            Ok(h) => h,
            Err(_) => return Ok(vec![packet.to_vec()]),
        };

        let payload = tcp.payload(tcp_buf);
        if parse_client_hello(payload).is_err() {
            return Ok(vec![packet.to_vec()]);
        }

        // Build decoy with low TTL
        let mut decoy = packet.to_vec();
        let decoy_payload = self.decoy_payload.as_deref().unwrap_or(payload);

        // Replace payload in decoy if a custom one was provided
        if self.decoy_payload.is_some() {
            let payload_start = ip.header_len + tcp.header_len;
            let new_len = payload_start + decoy_payload.len();
            decoy.resize(new_len, 0);
            decoy[payload_start..].copy_from_slice(decoy_payload);
            // Update IP total length
            let tl = new_len as u16;
            decoy[2] = (tl >> 8) as u8;
            decoy[3] = (tl & 0xff) as u8;
        }

        IpHeader::set_ttl(&mut decoy, self.decoy_ttl);

        log::debug!(
            "ttl_manip: sending decoy ttl={} then real ttl={}",
            self.decoy_ttl, ip.ttl
        );

        // Decoy first, then the real packet
        Ok(vec![decoy, packet.to_vec()])
    }
}
