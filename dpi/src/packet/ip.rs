use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProto {
    Tcp,
    Udp,
    Other(u8),
}

#[derive(Debug, Clone)]
pub struct IpHeader {
    pub version: u8,
    pub ihl: u8,         // header length in 32-bit words
    pub ttl: u8,
    pub proto: IpProto,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub header_len: usize,
}

#[derive(Debug, Error)]
pub enum IpParseError {
    #[error("packet too short: need {need} bytes, have {have}")]
    TooShort { need: usize, have: usize },
    #[error("unsupported IP version: {0}")]
    BadVersion(u8),
}

impl IpHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, IpParseError> {
        if buf.len() < 20 {
            return Err(IpParseError::TooShort { need: 20, have: buf.len() });
        }

        let version = buf[0] >> 4;
        if version != 4 {
            return Err(IpParseError::BadVersion(version));
        }

        let ihl = buf[0] & 0x0f;
        let header_len = (ihl as usize) * 4;

        if buf.len() < header_len {
            return Err(IpParseError::TooShort { need: header_len, have: buf.len() });
        }

        let proto = match buf[9] {
            6  => IpProto::Tcp,
            17 => IpProto::Udp,
            n  => IpProto::Other(n),
        };

        Ok(IpHeader {
            version,
            ihl,
            ttl: buf[8],
            proto,
            src: [buf[12], buf[13], buf[14], buf[15]],
            dst: [buf[16], buf[17], buf[18], buf[19]],
            header_len,
        })
    }

    /// Write the TTL field back into a raw IPv4 packet buffer and recompute the header checksum.
    pub fn set_ttl(buf: &mut [u8], ttl: u8) {
        buf[8] = ttl;
        recompute_ipv4_checksum(buf);
    }
}

fn recompute_ipv4_checksum(buf: &mut [u8]) {
    let ihl = ((buf[0] & 0x0f) as usize) * 4;
    buf[10] = 0;
    buf[11] = 0;
    let sum = ipv4_checksum(&buf[..ihl]);
    buf[10] = (sum >> 8) as u8;
    buf[11] = (sum & 0xff) as u8;
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
