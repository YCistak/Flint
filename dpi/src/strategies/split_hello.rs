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

        eprintln!(
            "[flint-dpi] split_hello: TLS ClientHello detected (SNI={:?}, payload_len={})",
            hello.sni, hello.payload_len
        );

        let split = self.split_pos.min(hello.payload_len.saturating_sub(1)).max(1);

        let first_payload  = &payload[..split];
        let second_payload = &payload[split..];

        let pkt1 = build_tcp_packet(&ip, &tcp, first_payload,  tcp.seq);
        let pkt2 = build_tcp_packet(&ip, &tcp, second_payload, tcp.seq + split as u32);

        eprintln!(
            "[flint-dpi] split_hello: applied split at byte {}/{} (SNI={:?}) -> 2 segments ({} + {} payload bytes)",
            split, hello.payload_len, hello.sni,
            first_payload.len(), second_payload.len()
        );

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
    // Zero-initialized; we re-build from scratch using known offsets rather
    // than copying the original buffer so lengths and checksum are always
    // correct.
    let mut pkt     = vec![0u8; total_len];

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{IpHeader, IpProto, TcpHeader};
    use crate::packet::tcp::{FLAG_ACK, FLAG_PSH};

    /// Build a minimal but well-formed IPv4 + TCP segment carrying a TLS
    /// ClientHello with the given SNI, as the capture layer would hand it to us.
    fn client_hello_packet(sni: &str) -> Vec<u8> {
        // ── ClientHello body (after the 4-byte handshake header) ──
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // ProtocolVersion TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // Random
        body.push(0); // SessionID length = 0
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // CipherSuites: len 2, TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&[0x01, 0x00]); // CompressionMethods: len 1, null

        // SNI extension
        let name = sni.as_bytes();
        let mut sni_ext = Vec::new();
        let list_len = (1 + 2 + name.len()) as u16; // name_type + name_len + name
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0); // name_type = host_name
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);

        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]); // ext_type = SNI
        ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext);

        body.extend_from_slice(&(ext.len() as u16).to_be_bytes()); // Extensions length
        body.extend_from_slice(&ext);

        // ── Handshake header + TLS record header ──
        let mut hs = vec![0x01]; // HandshakeType: ClientHello
        let body_len = body.len() as u32;
        hs.extend_from_slice(&body_len.to_be_bytes()[1..4]); // u24 length
        hs.extend_from_slice(&body);

        let mut tls = vec![0x16, 0x03, 0x01]; // Handshake, TLS 1.0 record version
        tls.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        tls.extend_from_slice(&hs);

        // ── TCP header (20 bytes, no options) ──
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&50000u16.to_be_bytes()); // src port
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes()); // dst port
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes()); // seq
        tcp[8..12].copy_from_slice(&2000u32.to_be_bytes()); // ack
        tcp[12] = 5 << 4; // data offset = 5 words
        tcp[13] = FLAG_PSH | FLAG_ACK;
        tcp[14..16].copy_from_slice(&64240u16.to_be_bytes()); // window
        tcp.extend_from_slice(&tls);

        // ── IP header (20 bytes, no options) ──
        let total = 20 + tcp.len();
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        ip[6] = 0x40; // DF
        ip[8] = 64; // TTL
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&[192, 168, 1, 45]); // src
        ip[16..20].copy_from_slice(&[140, 82, 121, 6]); // dst
        ip.extend_from_slice(&tcp);
        ip
    }

    /// Regression test for the `copy_from_slice` length-mismatch panic that
    /// crashed the capture thread the moment a ClientHello was detected.
    #[test]
    fn splits_client_hello_into_two_valid_segments() {
        let pkt = client_hello_packet("example.com");
        let out = SplitHelloStrategy::default()
            .apply(&pkt)
            .expect("strategy must not error");

        assert_eq!(out.len(), 2, "ClientHello must be split into two segments");

        // Both fragments must be parseable IPv4/TCP packets.
        let seqs: Vec<u32> = out
            .iter()
            .map(|frag| {
                let ip = IpHeader::parse(frag).expect("valid IP header");
                assert_eq!(ip.proto, IpProto::Tcp);
                let tcp = TcpHeader::parse(&frag[ip.header_len..]).expect("valid TCP header");
                tcp.seq
            })
            .collect();

        // split_pos defaults to 1: first segment carries 1 payload byte, and the
        // second segment's sequence number is advanced by that amount.
        assert_eq!(seqs[1], seqs[0] + 1, "second segment seq must follow the split");

        // The two payloads must reconstruct the original TCP payload exactly.
        let orig_ip = IpHeader::parse(&pkt).unwrap();
        let orig_tcp = TcpHeader::parse(&pkt[orig_ip.header_len..]).unwrap();
        let orig_payload = orig_tcp.payload(&pkt[orig_ip.header_len..]).to_vec();

        let mut rebuilt = Vec::new();
        for frag in &out {
            let ip = IpHeader::parse(frag).unwrap();
            let tcp = TcpHeader::parse(&frag[ip.header_len..]).unwrap();
            rebuilt.extend_from_slice(tcp.payload(&frag[ip.header_len..]));
        }
        assert_eq!(rebuilt, orig_payload, "fragments must reassemble to the original payload");
    }

    #[test]
    fn passes_through_non_tls_packet() {
        // A TCP segment whose payload is not a TLS ClientHello is returned as-is.
        let mut pkt = client_hello_packet("example.com");
        // Corrupt the TLS content type so parse_client_hello rejects it.
        let ip_len = (pkt[0] & 0x0f) as usize * 4;
        pkt[ip_len + 20] = 0x00; // first payload byte (was 0x16 handshake)
        let out = SplitHelloStrategy::default().apply(&pkt).unwrap();
        assert_eq!(out.len(), 1, "non-TLS traffic must pass through unmodified");
        assert_eq!(out[0], pkt);
    }
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
