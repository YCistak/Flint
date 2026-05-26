use thiserror::Error;

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq:      u32,
    pub ack:      u32,
    pub data_off: u8,   // header length in 32-bit words
    pub flags:    u8,
    pub window:   u16,
    pub header_len: usize,
}

pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_ACK: u8 = 0x10;
pub const FLAG_PSH: u8 = 0x08;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_FIN: u8 = 0x01;

#[derive(Debug, Error)]
pub enum TcpParseError {
    #[error("buffer too short: need {need}, have {have}")]
    TooShort { need: usize, have: usize },
    #[error("invalid data offset: {0}")]
    BadDataOffset(u8),
}

impl TcpHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, TcpParseError> {
        if buf.len() < 20 {
            return Err(TcpParseError::TooShort { need: 20, have: buf.len() });
        }

        let data_off = buf[12] >> 4;
        if data_off < 5 {
            return Err(TcpParseError::BadDataOffset(data_off));
        }
        let header_len = (data_off as usize) * 4;

        if buf.len() < header_len {
            return Err(TcpParseError::TooShort { need: header_len, have: buf.len() });
        }

        Ok(TcpHeader {
            src_port:   u16::from_be_bytes([buf[0], buf[1]]),
            dst_port:   u16::from_be_bytes([buf[2], buf[3]]),
            seq:        u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            ack:        u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            data_off,
            flags:      buf[13],
            window:     u16::from_be_bytes([buf[14], buf[15]]),
            header_len,
        })
    }

    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.header_len..]
    }
}
