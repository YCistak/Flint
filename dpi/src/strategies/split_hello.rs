//! Split-Hello strategy: fragment the TLS ClientHello across two TCP segments.
//!
//! Many DPI engines reassemble TCP streams but only inspect the *first* segment
//! for the ClientHello / SNI.  Sending the ClientHello split at byte `split_pos`
//! causes those engines to see an incomplete record in the first segment and
//! miss the SNI, while the server's full TCP reassembly sees the complete message.

use crate::capture::CaptureError;
use crate::packet::{IpHeader, IpProto, TcpHeader};
use crate::packet::tls::parse_client_hello;
use super::Strategy;

/// Split the TLS ClientHello at `split_pos` bytes into the TLS record payload.
/// A value of 1 (splitting after the first byte of the record) is the most
/// effective against simple pattern matchers.
pub struct SplitHelloStrategy {
    pub split_pos: usize,
}

impl Default for SplitHelloStrategy {
    fn default() -> Self {
        SplitHelloStrategy { split_pos: 1 }
    }
}

impl Strategy for SplitHelloStrategy {
    fn apply(&self, packet: &[u8]) -> Result<Vec<Vec<u8>>, CaptureError> {
        // Parse IP header
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
        if payload.is_empty() {
            return Ok(vec![packet.to_vec()]);
        }

        // Only act on TLS ClientHello
        let hello = match parse_client_hello(payload) {
            Ok(h) => h,
            Err(_) => return Ok(vec![packet.to_vec()]),
        };

        let split = self.split_pos.min(hello.payload_len.saturating_sub(1)).max(1);

        let first_payload  = &payload[..split];
        let second_payload = &payload[split..];

        let pkt1 = build_tcp_packet(&ip, &tcp, first_payload,  tcp.seq);
        let pkt2 = build_tcp_packet(&ip, &tcp, second_payload, tcp.seq + split as u32);

        log::debug!(
            "split_hello: SNI={:?} split at byte {}/{}",
            hello.sni, split, hello.payload_len
        );

        Ok(vec![pkt1, pkt2])
    }
}

/// Rebuild a raw IPv4/TCP packet with a new payload, updating lengths and checksums.
fn build_tcp_packet(ip: &IpHeader, tcp: &TcpHeader, payload: &[u8], seq: u32) -> Vec<u8> {
    let tcp_hdr_len = tcp.header_len;
    let total_len   = ip.header_len + tcp_hdr_len + payload.len();
    let mut pkt     = vec![0u8; total_len];

    // Copy original IP header and update total length
    pkt[..ip.header_len].copy_from_slice(&[0u8; 60][..0]); // zero first
    // We re-build from scratch using known offsets rather than copying
    // the original buffer so that lengths and checksum are always correct.

    // IP header (20 bytes, no options)
    pkt[0]  = 0x45; // version=4, IHL=5
    pkt[1]  = 0;    // DSCP/ECN
    let tl  = total_len as u16;
    pkt[2]  = (tl >> 8) as u8;
    pkt[3]  = (tl & 0xff) as u8;
    pkt[6]  = 0x40; // DF flag
    pkt[8]  = ip.ttl;
    pkt[9]  = 6;    // TCP
    pkt[12..16].copy_from_slice(&ip.src);
    pkt[16..20].copy_from_slice(&ip.dst);
    IpHeader::set_ttl(&mut pkt, ip.ttl); // also recomputes checksum

    // TCP header
    let t = &mut pkt[ip.header_len..ip.header_len + tcp_hdr_len];
    t[0]  = (tcp.src_port >> 8) as u8;
    t[1]  = (tcp.src_port & 0xff) as u8;
    t[2]  = (tcp.dst_port >> 8) as u8;
    t[3]  = (tcp.dst_port & 0xff) as u8;
    t[4]  = (seq >> 24) as u8;
    t[5]  = (seq >> 16) as u8;
    t[6]  = (seq >> 8)  as u8;
    t[7]  = (seq & 0xff) as u8;
    t[8]  = (tcp.ack >> 24) as u8;
    t[9]  = (tcp.ack >> 16) as u8;
    t[10] = (tcp.ack >> 8)  as u8;
    t[11] = (tcp.ack & 0xff) as u8;
    t[12] = (tcp.data_off << 4) | 0;
    t[13] = tcp.flags;
    t[14] = (tcp.window >> 8) as u8;
    t[15] = (tcp.window & 0xff) as u8;
    // checksum (16-17) left zero — filled below

    // Payload
    pkt[ip.header_len + tcp_hdr_len..].copy_from_slice(payload);

    // TCP checksum
    let cksum = tcp_checksum(&pkt, ip.header_len, tcp_hdr_len + payload.len());
    pkt[ip.header_len + 16] = (cksum >> 8) as u8;
    pkt[ip.header_len + 17] = (cksum & 0xff) as u8;

    pkt
}

fn tcp_checksum(pkt: &[u8], ip_hdr_len: usize, tcp_len: usize) -> u16 {
    // Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + tcp_len(2)
    let mut sum: u32 = 0;
    // src
    sum += u16::from_be_bytes([pkt[12], pkt[13]]) as u32;
    sum += u16::from_be_bytes([pkt[14], pkt[15]]) as u32;
    // dst
    sum += u16::from_be_bytes([pkt[16], pkt[17]]) as u32;
    sum += u16::from_be_bytes([pkt[18], pkt[19]]) as u32;
    // proto=6, len
    sum += 6u32;
    sum += tcp_len as u32;

    // TCP segment
    let tcp_seg = &pkt[ip_hdr_len..ip_hdr_len + tcp_len];
    let mut i = 0;
    while i + 1 < tcp_seg.len() {
        sum += u16::from_be_bytes([tcp_seg[i], tcp_seg[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_seg.len() {
        sum += (tcp_seg[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
