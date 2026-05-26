pub mod split_hello;
pub mod ttl;

pub use split_hello::SplitHelloStrategy;
pub use ttl::TtlStrategy;

use crate::capture::CaptureError;

/// A DPI bypass strategy transforms an intercepted raw IPv4 packet
/// (IP header + TCP header + payload) into one or more packets to inject.
pub trait Strategy {
    /// Given the original raw packet bytes, produce the replacement packets
    /// to send.  If the packet does not match (e.g. not a TLS ClientHello),
    /// return the original unchanged.
    fn apply(&self, packet: &[u8]) -> Result<Vec<Vec<u8>>, CaptureError>;
}
