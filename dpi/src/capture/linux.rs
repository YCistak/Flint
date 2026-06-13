//! Linux packet interception via nfqueue.
//!
//! Requires the kernel module `nfnetlink_queue` and an iptables rule such as:
//!   iptables -I OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0
//! to divert packets into queue #0 before this handle is opened.

use nfq::{Message, Queue, Verdict};

use super::{CaptureError, OwnedPacket};

/// Per-packet tracing is extremely verbose (two lines per packet) and only
/// useful when diagnosing capture/parse issues.  It is off by default and
/// enabled with `FLINT_DPI_TRACE=1`.  The env var is read once and cached.
fn trace_enabled() -> bool {
    use std::sync::OnceLock;
    static TRACE: OnceLock<bool> = OnceLock::new();
    *TRACE.get_or_init(|| {
        matches!(
            std::env::var("FLINT_DPI_TRACE").as_deref(),
            Ok("1") | Ok("true")
        )
    })
}

pub struct PacketHandle {
    queue: Queue,
    /// The most recently received message, awaiting a verdict.  The verdict is
    /// deliberately deferred until *after* the strategy layer has run, so that
    /// a transformed packet (e.g. a split ClientHello) can be DROPped while a
    /// pass-through packet is ACCEPTed.  See `recv` / `accept` / `drop_original`.
    pending: Option<Message>,
}

impl PacketHandle {
    /// Open nfqueue number `queue_num`.  The caller must have set up the
    /// iptables/nftables rule that directs traffic into this queue.
    pub fn open(queue_num: u16) -> Result<Self, CaptureError> {
        eprintln!("[flint-dpi] capture: opening nfqueue, binding to queue #{}", queue_num);
        let mut queue = Queue::open()
            .map_err(|e| CaptureError::Init(e.to_string()))?;
        queue
            .bind(queue_num)
            .map_err(|e| {
                eprintln!("[flint-dpi] capture: bind to queue #{} FAILED: {}", queue_num, e);
                CaptureError::Init(e.to_string())
            })?;
        eprintln!("[flint-dpi] capture: bound to queue #{}, ready to receive packets", queue_num);
        Ok(PacketHandle { queue, pending: None })
    }

    /// Block until the next packet arrives from the kernel queue.
    ///
    /// The verdict is **not** issued here.  The returned packet is held pending
    /// in the handle; the caller must subsequently call exactly one of
    /// [`accept`](Self::accept) or [`drop_original`](Self::drop_original) to
    /// release it back to the kernel.  Deferring the verdict is what lets the
    /// strategy layer decide between ACCEPT (pass-through) and DROP (we injected
    /// replacement fragments instead).
    pub fn recv(&mut self) -> Result<OwnedPacket, CaptureError> {
        // Defensive: if a previous packet was never verdicted (programming
        // error in the loop), accept it now so the kernel queue does not stall.
        if let Some(mut stale) = self.pending.take() {
            stale.set_verdict(Verdict::Accept);
            let _ = self.queue.verdict(stale);
        }

        let msg = self
            .queue
            .recv()
            .map_err(|e| CaptureError::Recv(e.to_string()))?;

        let id   = msg.get_packet_id() as u64;
        let data = msg.get_payload().to_vec();

        if trace_enabled() {
            // Dump the first 20 bytes (the IPv4 header) as hex so capture/parse
            // issues can be diagnosed; the leading byte's high nibble should be
            // 0x4 (IPv4) or the strategy's IP parse rejects the packet.
            let preview = data.len().min(20);
            let hex: String = data[..preview]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            eprintln!(
                "[flint-dpi] capture: received packet id={} len={} (verdict deferred); first {} bytes: {}",
                id, data.len(), preview, hex
            );
        }

        self.pending = Some(msg);

        Ok(OwnedPacket { data, id })
    }

    /// Verdict the pending packet as ACCEPT — pass it through to the network
    /// unmodified.  Used when the strategy did not transform the packet.
    pub fn accept(&mut self) -> Result<(), CaptureError> {
        match self.pending.take() {
            Some(mut msg) => {
                let id = msg.get_packet_id() as u64;
                msg.set_verdict(Verdict::Accept);
                self.queue
                    .verdict(msg)
                    .map_err(|e| CaptureError::Recv(e.to_string()))?;
                if trace_enabled() {
                    eprintln!("[flint-dpi] capture: verdicted packet id={} (Accept)", id);
                }
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Verdict the pending packet as DROP — discard the original.  Used after
    /// the strategy has injected replacement fragments (e.g. a split
    /// ClientHello), so that only those fragments reach the network and the
    /// original is not duplicated.
    pub fn drop_original(&mut self) -> Result<(), CaptureError> {
        match self.pending.take() {
            Some(mut msg) => {
                let id = msg.get_packet_id() as u64;
                msg.set_verdict(Verdict::Drop);
                self.queue
                    .verdict(msg)
                    .map_err(|e| CaptureError::Recv(e.to_string()))?;
                eprintln!("[flint-dpi] capture: verdicted packet id={} (Drop — original suppressed)", id);
                Ok(())
            }
            None => Ok(()),
        }
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
