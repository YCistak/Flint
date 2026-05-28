//! C-compatible FFI surface for the DPI bypass engine.
//!
//! This module is the only public API visible across the language boundary.
//! Go calls these three functions through CGo; everything else is internal.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicUsize;
use std::sync::{Mutex, OnceLock};
use std::thread;

// ── Status constants (must match flint_dpi.h) ────────────────────────────────

const DPI_OK: i32                  =  0;
const DPI_ERR_ALREADY_RUNNING: i32 = -1;
const DPI_ERR_NOT_RUNNING: i32     = -2;

pub const DPI_STATUS_STOPPED: i32  =  0;
pub const DPI_STATUS_RUNNING: i32  =  1;
pub const DPI_STATUS_ERROR: i32    =  2;

// ── Global state ─────────────────────────────────────────────────────────────

/// Overall engine status, read by dpi_status().
static STATE: AtomicI32  = AtomicI32::new(DPI_STATUS_STOPPED);
/// Cooperative stop signal polled by the capture loop.
static STOP:  AtomicBool = AtomicBool::new(false);

fn thread_slot() -> &'static Mutex<Option<thread::JoinHandle<()>>> {
    static SLOT: OnceLock<Mutex<Option<thread::JoinHandle<()>>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

// ── iptables helpers (Linux only) ─────────────────────────────────────────────

/// Returns true if the NFQUEUE redirect rule is already present in OUTPUT.
#[cfg(target_os = "linux")]
fn iptables_rule_exists() -> bool {
    std::process::Command::new("iptables")
        .args([
            "-C", "OUTPUT",
            "-p", "tcp", "--dport", "443",
            "-j", "NFQUEUE", "--queue-num", "0",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Adds the NFQUEUE redirect rule, skipping if it already exists.
#[cfg(target_os = "linux")]
fn iptables_add() {
    eprintln!("[flint-dpi] iptables_add: entered");

    if iptables_rule_exists() {
        eprintln!("[flint-dpi] iptables_add: rule already present, skipping");
        log::debug!("iptables: NFQUEUE rule already present, skipping");
        return;
    }

    eprintln!("[flint-dpi] iptables_add: running iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0");

    match std::process::Command::new("iptables")
        .args([
            "-A", "OUTPUT",
            "-p", "tcp", "--dport", "443",
            "-j", "NFQUEUE", "--queue-num", "0",
        ])
        .output()
    {
        Ok(out) => {
            eprintln!(
                "[flint-dpi] iptables_add: exit={} stdout={:?} stderr={:?}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
            if out.status.success() {
                log::info!("iptables: NFQUEUE rule added");
            } else {
                log::warn!("iptables: add rule failed (exit {})", out.status);
            }
        }
        Err(e) => {
            eprintln!("[flint-dpi] iptables_add: failed to exec iptables: {}", e);
            log::warn!("iptables: add rule error: {}", e);
        }
    }

    eprintln!("[flint-dpi] iptables_add: done");
}

/// Removes the NFQUEUE redirect rule.
#[cfg(target_os = "linux")]
fn iptables_remove() {
    match std::process::Command::new("iptables")
        .args([
            "-D", "OUTPUT",
            "-p", "tcp", "--dport", "443",
            "-j", "NFQUEUE", "--queue-num", "0",
        ])
        .status()
    {
        Ok(s) if s.success() => log::info!("iptables: NFQUEUE rule removed"),
        Ok(s) => log::warn!("iptables: remove rule failed (exit {})", s),
        Err(e) => log::warn!("iptables: remove rule error: {}", e),
    }
}

// ── Cleanup handlers (signal + panic) ────────────────────────────────────────

// Previous SIGTERM/SIGINT handlers saved at installation time (Go's handlers).
// We chain to them so Go's runtime signal machinery still runs after our cleanup.
#[cfg(target_os = "linux")]
static PREV_SIGTERM: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static PREV_SIGINT: AtomicUsize = AtomicUsize::new(0);

/// Installs a Rust panic hook and SIGTERM/SIGINT handlers that both call
/// `iptables_remove()` before chaining to the previously installed handler
/// (which is Go's runtime handler).  Safe to call multiple times — installs
/// exactly once via `Once`.
#[cfg(target_os = "linux")]
fn install_cleanup_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Panic hook: run iptables cleanup, then the previous hook (if any).
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            eprintln!("[flint-dpi] panic detected — removing iptables NFQUEUE rule");
            iptables_remove();
            prev_hook(info);
        }));

        // Signal handlers: save whatever was there before (Go's handler) so
        // we can chain to it after cleanup.
        // SA_RESETHAND: the disposition is restored to SIG_DFL before our
        // handler is invoked, so a second signal during cleanup terminates
        // the process without looping.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = signal_cleanup as *const () as usize;
            sa.sa_flags = libc::SA_RESETHAND;
            libc::sigemptyset(&mut sa.sa_mask);

            let mut old: libc::sigaction = std::mem::zeroed();

            libc::sigaction(libc::SIGTERM, &sa, &mut old);
            PREV_SIGTERM.store(old.sa_sigaction, Ordering::SeqCst);

            libc::sigaction(libc::SIGINT, &sa, &mut old);
            PREV_SIGINT.store(old.sa_sigaction, Ordering::SeqCst);
        }
    });
}

/// Signal handler for SIGTERM and SIGINT.  Removes the iptables rule, then
/// chains to Go's previously installed handler so Go's shutdown sequence
/// (and its own defer-based cleanup) can proceed normally.
#[cfg(target_os = "linux")]
extern "C" fn signal_cleanup(sig: libc::c_int) {
    iptables_remove();

    // SIG_DFL = 0, SIG_IGN = 1; anything above 1 is a real handler address.
    let prev = if sig == libc::SIGTERM {
        PREV_SIGTERM.load(Ordering::SeqCst)
    } else {
        PREV_SIGINT.load(Ordering::SeqCst)
    };

    if prev > 1 {
        // Call Go's handler.  SA_RESETHAND already reset the disposition to
        // SIG_DFL, so if Go's handler re-raises the signal it will terminate.
        unsafe {
            let f: extern "C" fn(libc::c_int) = std::mem::transmute(prev);
            f(sig);
        }
    }
    // If prev was SIG_DFL (0) or SIG_IGN (1): SA_RESETHAND has already
    // restored SIG_DFL, so the process will terminate on the next delivery.
}

// ── Public C API ─────────────────────────────────────────────────────────────

/// Start the DPI bypass engine in a background thread.
/// Returns 0 on success, -1 if already running.
#[no_mangle]
pub extern "C" fn dpi_start() -> i32 {
    // CAS: STOPPED → RUNNING.  If it fails the engine is already up.
    if STATE
        .compare_exchange(
            DPI_STATUS_STOPPED,
            DPI_STATUS_RUNNING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_err()
    {
        return DPI_ERR_ALREADY_RUNNING;
    }

    #[cfg(target_os = "linux")]
    install_cleanup_handlers();

    #[cfg(target_os = "linux")]
    iptables_add();

    STOP.store(false, Ordering::SeqCst);

    let handle = thread::spawn(run_capture_loop);
    *thread_slot().lock().unwrap() = Some(handle);

    DPI_OK
}

/// Stop the DPI bypass engine.
/// Returns 0 on success, -2 if it was not running.
#[no_mangle]
pub extern "C" fn dpi_stop() -> i32 {
    // CAS: RUNNING → STOPPED.
    if STATE
        .compare_exchange(
            DPI_STATUS_RUNNING,
            DPI_STATUS_STOPPED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_err()
    {
        return DPI_ERR_NOT_RUNNING;
    }

    // Signal the loop, then drop the handle without joining so we don't block
    // the calling goroutine.
    STOP.store(true, Ordering::SeqCst);
    *thread_slot().lock().unwrap() = None;

    #[cfg(target_os = "linux")]
    iptables_remove();

    DPI_OK
}

/// Return the current engine status: 0=stopped, 1=running, 2=error.
#[no_mangle]
pub extern "C" fn dpi_status() -> i32 {
    STATE.load(Ordering::SeqCst)
}

// ── Capture loop (runs inside the background thread) ─────────────────────────

fn run_capture_loop() {
    use crate::strategies::SplitHelloStrategy;

    log::info!("DPI capture loop starting");

    let strategy = SplitHelloStrategy::default();

    if let Err(e) = platform_loop(&strategy) {
        log::error!("DPI capture loop error: {}", e);
        STATE.store(DPI_STATUS_ERROR, Ordering::SeqCst);
        return;
    }

    // Normal exit: ensure state is STOPPED (dpi_stop() already set it, but be
    // defensive in case the loop exits for another reason).
    let _ = STATE.compare_exchange(
        DPI_STATUS_RUNNING,
        DPI_STATUS_STOPPED,
        Ordering::SeqCst,
        Ordering::SeqCst,
    );

    log::info!("DPI capture loop stopped");
}

// ── Platform dispatch ─────────────────────────────────────────────────────────

#[allow(unused_variables)]
fn platform_loop(
    strategy: &dyn crate::strategies::Strategy,
) -> Result<(), crate::capture::CaptureError> {
    #[cfg(target_os = "linux")]
    return linux_loop(strategy);

    // macOS / Windows capture loops are not yet integrated; the thread idles
    // until dpi_stop() signals it.  The DPI strategies and parsers are fully
    // implemented — only the verdict/reinject wiring is pending.
    #[cfg(not(target_os = "linux"))]
    {
        log::warn!(
            "DPI capture loop not yet integrated on this platform — \
             strategies available but idling"
        );
        while !STOP.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        Ok(())
    }
}

// ── Linux: nfqueue capture loop ───────────────────────────────────────────────
//
// NOTE on verdict flow: the current recv() implementation accepts each packet
// before returning it, so the strategy's replacement packets are injected
// *in addition* to the original.  A future revision should:
//   1. Change recv() to hold the verdict.
//   2. Drop the original after injecting all replacement packets.
// This is tracked as a TODO in PLANNED.md (end-to-end integration).

#[cfg(target_os = "linux")]
fn linux_loop(
    strategy: &dyn crate::strategies::Strategy,
) -> Result<(), crate::capture::CaptureError> {
    use crate::capture::PacketHandle;

    let mut handle = PacketHandle::open(0)?;

    while !STOP.load(Ordering::Relaxed) {
        let pkt = handle.recv()?;

        match strategy.apply(&pkt.data) {
            Ok(replacements) => {
                // If the strategy produced a different set of packets (e.g. two
                // fragments for split-hello), inject them.  The original was
                // already accepted by recv(); see note above.
                if replacements.len() != 1
                    || replacements[0] != pkt.data
                {
                    for r in &replacements {
                        if let Err(e) = handle.send(r) {
                            log::warn!("DPI send error: {}", e);
                        }
                    }
                }
            }
            Err(e) => log::warn!("strategy error: {}", e),
        }
    }

    Ok(())
}
