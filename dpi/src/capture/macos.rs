//! macOS packet capture via libpcap/BPF.
//!
//! libpcap on macOS reads from BPF devices.  Injection uses a raw socket
//! (same approach as Linux).  No kernel driver is required; however, the
//! process needs root or the `com.apple.security.network.client` entitlement
//! plus a BPF device opened with appropriate permissions.

use pcap::{Capture, Active, Device};

use super::{CaptureError, OwnedPacket};

pub struct PacketHandle {
    cap: Capture<Active>,
}

impl PacketHandle {
    /// Open a live capture on `iface` (e.g. "en0") filtered by `filter`
    /// (BPF filter string, e.g. "tcp port 443").
    pub fn open(iface: &str, filter: &str) -> Result<Self, CaptureError> {
        let device = Device::list()
            .map_err(|e| CaptureError::Init(e.to_string()))?
            .into_iter()
            .find(|d| d.name == iface)
            .ok_or_else(|| CaptureError::Init(format!("interface '{}' not found", iface)))?;

        let mut cap = Capture::from_device(device)
            .map_err(|e| CaptureError::Init(e.to_string()))?
            .immediate_mode(true)
            .open()
            .map_err(|e| CaptureError::Init(e.to_string()))?;

        cap.filter(filter, true)
            .map_err(|e| CaptureError::Init(e.to_string()))?;

        Ok(PacketHandle { cap })
    }

    /// Block until the next matching packet arrives.
    pub fn recv(&mut self) -> Result<OwnedPacket, CaptureError> {
        let pkt = self.cap.next_packet()
            .map_err(|e| CaptureError::Recv(e.to_string()))?;
        Ok(OwnedPacket {
            data: pkt.data.to_vec(),
            id:   0,
        })
    }

    /// Inject a raw packet via a BSD raw socket.
    pub fn send(&self, packet: &[u8]) -> Result<(), CaptureError> {
        if packet.len() < 20 {
            return Err(CaptureError::Send("packet too short".into()));
        }
        let dst = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let fd = unsafe { bsd_raw_socket() };
        if fd < 0 {
            return Err(CaptureError::Send("raw socket creation failed".into()));
        }
        set_ip_hdrincl(fd)?;
        bsd_sendto(fd, packet, dst)?;
        unsafe { libc_close(fd) };
        Ok(())
    }
}

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
const IP_HDRINCL:  i32 = 2; // macOS value differs from Linux

unsafe fn bsd_raw_socket() -> i32 {
    libc_socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
}

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

fn bsd_sendto(fd: i32, packet: &[u8], dst: std::net::Ipv4Addr) -> Result<(), CaptureError> {
    let mut addr = [0u8; 16];
    addr[1] = 2; // sin_family = AF_INET (big-endian on BSD)
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
