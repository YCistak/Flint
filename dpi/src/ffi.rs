//! C-compatible FFI surface for the DPI bypass engine.
//!
//! This module is the only public API visible across the language boundary.
//! Go calls these three functions through CGo; everything else is internal.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
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

// ── Firewall backend (Linux only) ────────────────────────────────────────────
//
// Modern distros ship `iptables` as a thin compat shim over nftables, while
// older ones use the legacy xtables backend.  We detect which is in play at
// runtime and drive the NFQUEUE redirect rule through the matching tool:
//   - nftables backend  → native `nft` commands in a dedicated `flint_dpi` table
//   - iptables-legacy    → classic `iptables -A/-D OUTPUT ... NFQUEUE` rules
// Both install the equivalent rule: tcp dport 443 → NFQUEUE queue 0.

/// Name of the dedicated nftables table we create so cleanup is a single
/// `nft delete table` and never touches the user's other rules.
#[cfg(target_os = "linux")]
const NFT_TABLE: &str = "flint_dpi";

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum FirewallBackend {
    Nftables,
    IptablesLegacy,
}

/// True if `cmd --version` runs successfully, i.e. the binary exists on PATH.
#[cfg(target_os = "linux")]
fn command_available(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Detect the firewall backend in use.  We treat the system as nftables-based
/// only when BOTH the `nft` tool is available AND `iptables --version` reports
/// the `nf_tables` backend (e.g. "iptables v1.8.x (nf_tables)").  Otherwise we
/// fall back to the legacy `iptables` path, which also covers the case where
/// `nft` is missing entirely.  The detected backend is logged.
#[cfg(target_os = "linux")]
fn detect_firewall_backend() -> FirewallBackend {
    let nft_available = command_available("nft");

    let iptables_is_nft = std::process::Command::new("iptables")
        .arg("--version")
        .output()
        .map(|o| {
            let v = String::from_utf8_lossy(&o.stdout);
            v.contains("nf_tables")
        })
        .unwrap_or(false);

    if nft_available && iptables_is_nft {
        eprintln!(
            "[flint-dpi] firewall: detected nftables backend \
             (nft available, iptables --version reports nf_tables) → using nft commands"
        );
        FirewallBackend::Nftables
    } else {
        eprintln!(
            "[flint-dpi] firewall: detected iptables-legacy backend \
             (nft_available={}, iptables_nf_tables={}) → using iptables commands",
            nft_available, iptables_is_nft
        );
        FirewallBackend::IptablesLegacy
    }
}

// ── iptables / nft helpers (Linux only) ───────────────────────────────────────

/// Adds the NFQUEUE redirect rule using whichever backend is detected.
#[cfg(target_os = "linux")]
fn iptables_add() {
    match detect_firewall_backend() {
        FirewallBackend::Nftables => nft_add(),
        FirewallBackend::IptablesLegacy => iptables_legacy_add(),
    }
}

/// Removes the NFQUEUE redirect rule using whichever backend is detected.
#[cfg(target_os = "linux")]
fn iptables_remove() {
    match detect_firewall_backend() {
        FirewallBackend::Nftables => nft_remove(),
        FirewallBackend::IptablesLegacy => iptables_legacy_remove(),
    }
}

// ── nftables backend ──────────────────────────────────────────────────────────

/// Run `nft <args>`, logging failures.  Returns true on exit code 0.
#[cfg(target_os = "linux")]
fn run_nft(args: &[&str]) -> bool {
    match std::process::Command::new("nft").args(args).output() {
        Ok(out) => {
            if !out.status.success() {
                eprintln!(
                    "[flint-dpi] nft {:?}: exit={} stderr={:?}",
                    args,
                    out.status,
                    String::from_utf8_lossy(&out.stderr),
                );
            }
            out.status.success()
        }
        Err(e) => {
            eprintln!("[flint-dpi] nft {:?}: exec failed: {}", args, e);
            false
        }
    }
}

/// Install the NFQUEUE rule via nftables in a dedicated `flint_dpi` table.
#[cfg(target_os = "linux")]
fn nft_add() {
    eprintln!("[flint-dpi] nft_add: entered (nftables backend)");

    // Start from a clean slate so repeated starts never stack duplicate rules.
    let _ = run_nft(&["delete", "table", "ip", NFT_TABLE]);

    let ok_table = run_nft(&["add", "table", "ip", NFT_TABLE]);
    let ok_chain = run_nft(&[
        "add", "chain", "ip", NFT_TABLE, "output",
        "{ type filter hook output priority 0; policy accept; }",
    ]);
    let ok_rule = run_nft(&[
        "add", "rule", "ip", NFT_TABLE, "output",
        "tcp", "dport", "443", "queue", "num", "0",
    ]);

    if ok_table && ok_chain && ok_rule {
        eprintln!(
            "[flint-dpi] nft_add: NFQUEUE rule installed (table ip {} → tcp dport 443 queue num 0)",
            NFT_TABLE
        );
        log::info!("nft: NFQUEUE rule added (table {})", NFT_TABLE);
    } else {
        eprintln!(
            "[flint-dpi] nft_add: failed to install rule (table={} chain={} rule={})",
            ok_table, ok_chain, ok_rule
        );
        log::warn!("nft: failed to add NFQUEUE rule");
    }
}

/// Remove the dedicated `flint_dpi` nftables table (and its rule).
#[cfg(target_os = "linux")]
fn nft_remove() {
    eprintln!(
        "[flint-dpi] nft_remove: deleting table ip {} (nftables backend)",
        NFT_TABLE
    );
    if run_nft(&["delete", "table", "ip", NFT_TABLE]) {
        log::info!("nft: NFQUEUE rule removed (table {})", NFT_TABLE);
    } else {
        log::warn!("nft: remove rule failed (table {} may not exist)", NFT_TABLE);
    }
}

// ── iptables-legacy backend ────────────────────────────────────────────────────

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

/// Adds the NFQUEUE redirect rule via legacy iptables, skipping if present.
#[cfg(target_os = "linux")]
fn iptables_legacy_add() {
    eprintln!("[flint-dpi] iptables_add: entered (iptables-legacy backend)");

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

/// Removes the NFQUEUE redirect rule via legacy iptables.
#[cfg(target_os = "linux")]
fn iptables_legacy_remove() {
    eprintln!("[flint-dpi] iptables_remove: removing rule (iptables-legacy backend)");
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

/// Installs a Rust panic hook that removes the NFQUEUE firewall rule before
/// chaining to the previous hook.  This is a best-effort safety net for an
/// unexpected panic in the capture thread.  Safe to call multiple times —
/// installs exactly once via `Once`.
///
/// We deliberately do **not** install SIGINT/SIGTERM handlers here.  The Go
/// runtime owns those signals, and the daemon's normal shutdown path already
/// calls `dpi_stop()` → `iptables_remove()` from ordinary (non-signal) context
/// via a deferred `manager.Stop()`.  An earlier version installed a `sigaction`
/// handler and chained to Go's `SA_SIGINFO` handler as a one-argument function;
/// that passed a NULL siginfo/ucontext to the Go runtime and segfaulted it on
/// Ctrl+C.  Spawning `nft`/`iptables` from signal context is also not
/// async-signal-safe.  A rule leaked by a hard kill is reclaimed on the next
/// start (`nft_add` deletes the table first; `iptables_add` checks for it).
#[cfg(target_os = "linux")]
fn install_cleanup_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            eprintln!("[flint-dpi] panic detected — removing iptables NFQUEUE rule");
            iptables_remove();
            prev_hook(info);
        }));
    });
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
// Verdict flow: recv() now holds the verdict instead of accepting eagerly.  For
// each packet we run the strategy first, then verdict:
//   - strategy transformed the packet (e.g. split ClientHello) → inject the
//     replacement fragments, then DROP the original so it is not duplicated.
//   - strategy passed the packet through unchanged → ACCEPT the original.

#[cfg(target_os = "linux")]
fn linux_loop(
    strategy: &dyn crate::strategies::Strategy,
) -> Result<(), crate::capture::CaptureError> {
    use crate::capture::PacketHandle;

    let mut handle = PacketHandle::open(0)?;

    while !STOP.load(Ordering::Relaxed) {
        // 1) Receive the packet (verdict deferred — held pending in the handle).
        let pkt = handle.recv()?;

        // 2-3) Run the strategy.  It parses IP/TCP and detects a TLS ClientHello
        //       internally; a non-matching packet is returned unchanged.
        match strategy.apply(&pkt.data) {
            Ok(replacements) => {
                let transformed =
                    replacements.len() != 1 || replacements[0] != pkt.data;

                if transformed {
                    // 4) ClientHello matched: inject the split fragments, then
                    //    DROP the original so only the fragments reach the wire.
                    let mut all_sent = true;
                    for r in &replacements {
                        if let Err(e) = handle.send(r) {
                            log::warn!("DPI send error: {}", e);
                            all_sent = false;
                        }
                    }

                    if all_sent {
                        handle.drop_original()?;
                    } else {
                        // A fragment failed to inject — fall back to ACCEPT so
                        // the connection is not silently broken.
                        log::warn!(
                            "DPI: fragment injection failed; accepting original to avoid stall"
                        );
                        handle.accept()?;
                    }
                } else {
                    // 5) Not a ClientHello (or strategy declined): pass through.
                    handle.accept()?;
                }
            }
            Err(e) => {
                // On strategy error, accept the original so traffic still flows.
                log::warn!("strategy error: {}", e);
                handle.accept()?;
            }
        }
    }

    Ok(())
}
