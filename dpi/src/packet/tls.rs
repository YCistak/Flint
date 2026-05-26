use thiserror::Error;

// TLS record types
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
// TLS handshake message types
const HANDSHAKE_CLIENT_HELLO: u8 = 1;

#[derive(Debug, Clone)]
pub struct TlsRecord {
    pub content_type: u8,
    pub version:      u16,
    pub payload_len:  usize,
    pub header_len:   usize, // always 5
}

#[derive(Debug, Clone)]
pub struct ClientHello {
    /// Byte offset of the start of the ClientHello *payload* within the full TCP payload.
    pub payload_offset: usize,
    pub payload_len:    usize,
    pub sni:            Option<String>,
}

#[derive(Debug, Error)]
pub enum TlsParseError {
    #[error("buffer too short")]
    TooShort,
    #[error("not a TLS record")]
    NotTls,
    #[error("not a ClientHello")]
    NotClientHello,
    #[error("malformed handshake")]
    Malformed,
}

impl TlsRecord {
    /// Parse the 5-byte TLS record header at the start of `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self, TlsParseError> {
        if buf.len() < 5 {
            return Err(TlsParseError::TooShort);
        }
        let content_type = buf[0];
        // Sanity-check: valid TLS content types are 20-23; version must look like 0x03xx
        if !(20..=23).contains(&content_type) || buf[1] != 0x03 {
            return Err(TlsParseError::NotTls);
        }
        Ok(TlsRecord {
            content_type,
            version:     u16::from_be_bytes([buf[1], buf[2]]),
            payload_len: u16::from_be_bytes([buf[3], buf[4]]) as usize,
            header_len:  5,
        })
    }

    pub fn is_handshake(&self) -> bool {
        self.content_type == CONTENT_TYPE_HANDSHAKE
    }
}

/// Try to parse a ClientHello from a TCP payload.
/// Returns `Err` if the payload is not a TLS ClientHello.
pub fn parse_client_hello(tcp_payload: &[u8]) -> Result<ClientHello, TlsParseError> {
    let rec = TlsRecord::parse(tcp_payload)?;
    if !rec.is_handshake() {
        return Err(TlsParseError::NotClientHello);
    }

    let hs = &tcp_payload[rec.header_len..];
    if hs.is_empty() || hs[0] != HANDSHAKE_CLIENT_HELLO {
        return Err(TlsParseError::NotClientHello);
    }
    if hs.len() < 4 {
        return Err(TlsParseError::Malformed);
    }

    // Handshake header: 1 byte type + 3 bytes length
    let hs_len = u24_to_usize(&hs[1..4]);
    let payload_offset = rec.header_len; // offset into tcp_payload where handshake msg starts
    let payload_len    = 4 + hs_len;     // type(1) + len(3) + body

    if hs.len() < payload_len {
        return Err(TlsParseError::Malformed);
    }

    let sni = extract_sni(&hs[4..4 + hs_len]);

    Ok(ClientHello { payload_offset, payload_len, sni })
}

/// Walk the ClientHello body (after the 4-byte handshake header) and extract SNI.
fn extract_sni(body: &[u8]) -> Option<String> {
    // ClientHello body layout (all big-endian):
    //   2  ProtocolVersion
    //   32 Random
    //   1  SessionID length  + data
    //   2  CipherSuites length + data
    //   1  CompressionMethods length + data
    //   2  Extensions length
    //   ...extensions...
    let mut pos = 0;

    // ProtocolVersion (2) + Random (32)
    pos += 34;
    if body.len() < pos + 1 { return None; }

    // SessionID
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    if body.len() < pos + 2 { return None; }

    // CipherSuites
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if body.len() < pos + 1 { return None; }

    // CompressionMethods
    let cm_len = body[pos] as usize;
    pos += 1 + cm_len;
    if body.len() < pos + 2 { return None; }

    // Extensions
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total;
    if body.len() < ext_end { return None; }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len  = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension (type 0)
            return parse_sni_ext(&body[pos..pos + ext_len]);
        }
        pos += ext_len;
    }

    None
}

fn parse_sni_ext(ext_data: &[u8]) -> Option<String> {
    // SNI extension data:
    //   2  server_name_list_length
    //   1  name_type (0 = host_name)
    //   2  name_length
    //   *  name
    if ext_data.len() < 5 { return None; }
    // name_type must be 0
    if ext_data[2] != 0 { return None; }
    let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
    if ext_data.len() < 5 + name_len { return None; }
    std::str::from_utf8(&ext_data[5..5 + name_len])
        .ok()
        .map(|s| s.to_owned())
}

fn u24_to_usize(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize)
}
