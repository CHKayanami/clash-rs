//! Android hosts own VPN routing. Exclude the core UID from the VPN, or install
//! a protector calling VpnService.protect(fd) before starting the core.
use std::{collections::HashMap, io, os::fd::{AsRawFd, OwnedFd, RawFd}, sync::{Arc, LazyLock, Mutex, RwLock, Weak}};

/// The descriptor is borrowed only for this synchronous call. Do not close or
/// retain it. Return an error when VpnService.protect reports failure.
pub type SocketProtector = Arc<dyn Fn(RawFd) -> io::Result<()> + Send + Sync>;

#[derive(Default)]
struct Protection {
    callback: RwLock<Option<SocketProtector>>,
}

impl Protection {
    fn set(&self, callback: Option<SocketProtector>) {
        *self.callback.write().unwrap() = callback;
    }

    fn protect(&self, fd: RawFd) -> io::Result<()> {
        let callback = self.callback.read().unwrap().clone();
        // The cloned Arc keeps host resources alive without holding the lock
        // while calling Java or allowing the callback to replace itself.
        match callback {
            Some(callback) => callback(fd),
            None => Ok(()),
        }
    }
}

static PROTECTION: Protection = Protection { callback: RwLock::new(None) };

/// Set before starting a VPN session. None requires host-side UID exclusion.
/// Clearing the callback does not wait for calls already in progress.
pub fn set_socket_protector(callback: Option<SocketProtector>) {
    PROTECTION.set(callback);
}

pub(crate) fn protect_socket(fd: RawFd) -> io::Result<()> {
    PROTECTION.protect(fd)
}

type PendingFd = Mutex<Option<OwnedFd>>;
static TUN_FDS: LazyLock<Mutex<HashMap<RawFd, Weak<PendingFd>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Retain this guard until the core thread has exited. It closes the descriptor
/// if startup fails before tun-rs takes ownership, releasing the VPN interface.
pub struct TunFdGuard {
    fd: RawFd,
    pending: Arc<PendingFd>,
}

impl TunFdGuard {
    /// Release a not-yet-adopted TUN when cancelling startup. Subsequent adoption
    /// fails instead of using a closed (possibly recycled) descriptor number.
    pub fn close_pending(&self) {
        self.pending.lock().unwrap().take();
    }
}

impl Drop for TunFdGuard {
    fn drop(&mut self) {
        let mut registry = TUN_FDS.lock().unwrap();
        if registry.get(&self.fd).is_some_and(|entry| entry.ptr_eq(&Arc::downgrade(&self.pending))) {
            registry.remove(&self.fd);
        }
    }
}

pub fn register_tun_fd(fd: OwnedFd) -> TunFdGuard {
    let number = fd.as_raw_fd();
    let pending = Arc::new(Mutex::new(Some(fd)));
    TUN_FDS.lock().unwrap().insert(number, Arc::downgrade(&pending));
    TunFdGuard { fd: number, pending }
}

pub(crate) fn take_registered_tun_fd(fd: RawFd) -> io::Result<Option<OwnedFd>> {
    let pending = TUN_FDS.lock().unwrap().get(&fd).and_then(Weak::upgrade);
    match pending {
        Some(pending) => pending.lock().unwrap().take().map(Some).ok_or_else(||
            io::Error::new(io::ErrorKind::InvalidInput, "TUN descriptor already adopted or startup cancelled")),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, Ordering};

    #[test]
    fn protection_propagates_rejection_and_supports_replacement() {
        let protection = Protection::default();
        assert!(protection.protect(7).is_ok());
        protection.set(Some(Arc::new(|_| Err(io::Error::new(
            io::ErrorKind::PermissionDenied, "VPN protection rejected",
        )))));
        assert_eq!(protection.protect(7).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let seen = Arc::new(AtomicI32::new(-1));
        let record = seen.clone();
        protection.set(Some(Arc::new(move |fd| { record.store(fd, Ordering::SeqCst); Ok(()) })));
        protection.protect(42).unwrap();
        assert_eq!(seen.load(Ordering::SeqCst), 42);
        protection.set(None);
        assert!(protection.protect(7).is_ok());
        // Exercise the public entrypoints without changing the default callback.
        assert!(protect_socket(-1).is_ok());
    }

    #[test]
    fn callback_can_reconfigure_protection_without_deadlocking() {
        let protection = Arc::new(Protection::default());
        let weak = Arc::downgrade(&protection);
        protection.set(Some(Arc::new(move |_| { weak.upgrade().unwrap().set(None); Ok(()) })));
        protection.protect(7).unwrap();
        assert!(protection.callback.read().unwrap().is_none());
    }
    #[test]
    fn unclaimed_tun_closes_on_startup_failure() {
        use std::{io::Read, os::unix::net::UnixStream};
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let guard = register_tun_fd(stream.into());
        drop(guard);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn adopted_tun_has_one_owner_and_cancelled_tun_cannot_be_reused() {
        use std::{io::{Read, Write}, os::unix::net::UnixStream};
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let fd = stream.as_raw_fd();
        let guard = register_tun_fd(stream.into());
        let owned = take_registered_tun_fd(fd).unwrap().unwrap();
        guard.close_pending();
        let mut stream = UnixStream::from(owned);
        stream.write_all(b"x").unwrap();
        let mut byte = [0];
        peer.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [b'x']);
        assert!(take_registered_tun_fd(fd).is_err());
        drop(guard);

        let (stream, mut peer) = UnixStream::pair().unwrap();
        let fd = stream.as_raw_fd();
        let guard = register_tun_fd(stream.into());
        guard.close_pending();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        assert!(take_registered_tun_fd(fd).is_err());
    }

}
