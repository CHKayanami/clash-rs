use std::{
    io,
    sync::{Mutex, atomic::{AtomicU8, Ordering}},
};

use libc::{SIGINT, SIGTERM, _exit};
use signal_hook_registry::{register, unregister};

const RUNNING: u8 = 0;
const STOP_REQUESTED: u8 = 1;
const RESTART_COMMITTED: u8 = 2;

static RESTART_STATE: AtomicU8 = AtomicU8::new(RUNNING);
static INSTALLED: Mutex<bool> = Mutex::new(false);

fn record_stop() {
    if RESTART_STATE.swap(STOP_REQUESTED, Ordering::Relaxed) == RESTART_COMMITTED {
        // SAFETY: _exit is async-signal-safe. The CLI commits only after
        // services, the runtime, and log writers have finished cleanup.
        unsafe { _exit(0) };
    }
}

pub(crate) fn install() -> io::Result<()> {
    let mut installed = INSTALLED.lock().unwrap();
    if !*installed {
        // SAFETY: record_stop uses only a lock-free atomic and _exit. The
        // registry chains this callback with Tokio's signal handler.
        let sigterm = unsafe { register(SIGTERM, record_stop) }?;
        if let Err(error) = unsafe { register(SIGINT, record_stop) } {
            unregister(sigterm);
            return Err(error);
        }
        *installed = true;
    }
    Ok(())
}

/// Commit a CLI restart after all cleanup. Returns false if a stop was requested.
pub fn commit_process_restart() -> bool {
    RESTART_STATE.compare_exchange(
        RUNNING, RESTART_COMMITTED, Ordering::Relaxed, Ordering::Relaxed,
    ).is_ok()
}
