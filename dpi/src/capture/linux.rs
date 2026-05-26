//! Linux packet interception via nfqueue.
//!
//! Requires the kernel module `nfnetlink_queue` and an iptables rule such as:
//!   iptables -I OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0
//! to divert packets into queue #0 before this handle is opened.

use nfq::{Queue, Verdict};

use super::{CaptureError, OwnedPacket};

pub struct PacketHandle {
    queue: Queue,
}

impl PacketHandle {
    /// Open nfqueue number `queue_num`.  The caller must have set up the
    /// iptables/nftables rule that directs traffic into this queue.
    pub fn open(queue_num: u16) -> Result<Self, CaptureError> {
        let mut queue = Queue::open()
            .map_err(|e| CaptureError::Init(e.to_string()))?;
        queue
            .bind(queue_num)
            .map_err(|e| CaptureError::Init(e.to_string()))?;
        Ok(PacketHandle { queue })
    }

    /// Block until the next packet arrives from the kernel queue.
    pub fn recv(&mut self) -> Result<OwnedPacket, CaptureError> {
        let mut msg = self
            .queue
            .recv()
            .map_err(|e| CaptureError::Recv(e.to_string()))?;

        let id   = msg.get_packet_id() as u64;
        let data = msg.get_payload().to_vec();

        // Default verdict: accept (pass through unmodified).
        // The strategy layer will call `send` with a modified copy instead.
        msg.set_verdict(Verdict::Accept);
        self.queue
            .verdict(msg)
            .map_err(|e| CaptureError::Recv(e.to_string()))?;

        Ok(OwnedPacket { data, id })
    }

    /// Re-inject a (possibly modified) raw IPv4 packet via a raw socket.
    pub fn send(&self, packet: &[u8]) -> Result<(), CaptureError> {
        use std::net::Ipv4Addr;

        let dst = if packet.len() >= 20 {
            Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])
        } else {
            return Err(CaptureError::Send("packet too short".into()));
        };

        // SAFETY: socket(AF_INET, SOCK_RAW, IPPROTO_RAW) — standard POSIX.
        let fd = unsafe { libc_socket(AF_INET, SOCK_RAW, IPPROTO_RAW) };
        if fd < 0 {
            return Err(CaptureError::Send("raw socket creation failed".into()));
        }
        // Enable IP_HDRINCL so the kernel does not prepend its own IP header.
        set_ip_hdrincl(fd)?;
        raw_sendto(fd, packet, dst)?;
        unsafe { libc_close(fd) };
        Ok(())
    }
}

// Thin libc wrappers to avoid pulling in the `libc` crate as a public dep.
extern "C" {
    #[link_name = "socket"]
    fn libc_socket(domain: i32, ty: i32, proto: i32) -> i32;
    #[link_name = "close"]
    fn libc_close(fd: i32) -> i32;
    #[link_name = "setsockopt"]
    fn libc_setsockopt(fd: i32, level: i32, name: i32, val: *const u8, len: u32) -> i32;
    #[link_name = "sendto"]
    fn libc_sendto(
        fd: i32, buf: *const u8, len: usize, flags: i32,
        addr: *const u8, addrlen: u32,
    ) -> isize;
}

const AF_INET:     i32 = 2;
const SOCK_RAW:    i32 = 3;
const IPPROTO_RAW: i32 = 255;
const IPPROTO_IP:  i32 = 0;
const IP_HDRINCL:  i32 = 3;

fn set_ip_hdrincl(fd: i32) -> Result<(), CaptureError> {
    let one: i32 = 1;
    let rc = unsafe {
        libc_setsockopt(fd, IPPROTO_IP, IP_HDRINCL,
                        &one as *const i32 as *const u8, 4)
    };
    if rc < 0 {
        Err(CaptureError::Send("setsockopt IP_HDRINCL failed".into()))
    } else {
        Ok(())
    }
}

fn raw_sendto(fd: i32, packet: &[u8], dst: std::net::Ipv4Addr) -> Result<(), CaptureError> {
    // sockaddr_in: sin_family(2) + sin_port(2) + sin_addr(4) + pad(8) = 16 bytes
    let mut addr = [0u8; 16];
    addr[0] = 2; // AF_INET (little-endian low byte)
    let octets = dst.octets();
    addr[4..8].copy_from_slice(&octets);

    let sent = unsafe {
        libc_sendto(fd, packet.as_ptr(), packet.len(), 0,
                    addr.as_ptr(), 16)
    };
    if sent < 0 {
        Err(CaptureError::Send("sendto failed".into()))
    } else {
        Ok(())
    }
}
