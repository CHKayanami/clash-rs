use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetNsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to switch netns: {0}")]
    SetnsFailed(i32),
}

use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

pub struct DaeNs {
    host_ns: OwnedFd,
    dae_ns: OwnedFd,
}

impl DaeNs {
    /// Creates a new network namespace for daens and captures the host namespace.
    pub fn new() -> Result<Self, NetNsError> {
        // Open host netns
        let host_file = File::open("/proc/thread-self/ns/net")?;
        let host_ns = host_file.into();

        // Create new namespace in an isolated thread so worker threads remain in host ns
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let res = (|| -> Result<OwnedFd, std::io::Error> {
                let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let ns_file = File::open("/proc/thread-self/ns/net")?;
                Ok(ns_file.into())
            })();
            let _ = tx.send(res);
        });

        let dae_ns = rx
            .recv()
            .map_err(|_| {
                NetNsError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Thread failed",
                ))
            })?
            .map_err(NetNsError::Io)?;

        Ok(Self { host_ns, dae_ns })
    }

    pub fn host_fd(&self) -> RawFd {
        self.host_ns.as_raw_fd()
    }

    pub fn dae_fd(&self) -> RawFd {
        self.dae_ns.as_raw_fd()
    }

    pub fn try_clone(&self) -> Result<Self, NetNsError> {
        let host_ns = self.host_ns.try_clone().map_err(NetNsError::Io)?;
        let dae_ns = self.dae_ns.try_clone().map_err(NetNsError::Io)?;
        Ok(Self { host_ns, dae_ns })
    }

    pub fn dae_file(&self) -> Result<File, NetNsError> {
        let cloned = self.dae_ns.try_clone().map_err(NetNsError::Io)?;
        Ok(File::from(cloned))
    }

    /// Executes a synchronous closure within the isolated daens network namespace.
    pub fn with_daens<F, R>(&self, f: F) -> Result<R, NetNsError>
    where
        F: FnOnce() -> R,
    {
        let host_file = File::open("/proc/thread-self/ns/net")?;
        let current_ns: OwnedFd = host_file.into();

        unsafe {
            if libc::setns(self.dae_ns.as_raw_fd(), libc::CLONE_NEWNET) != 0 {
                return Err(NetNsError::Io(std::io::Error::last_os_error()));
            }
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

        unsafe {
            if libc::setns(current_ns.as_raw_fd(), libc::CLONE_NEWNET) != 0 {
                eprintln!(
                    "FATAL: Failed to restore host netns after with_daens call"
                );
                std::process::abort();
            }
        }

        match result {
            Ok(val) => Ok(val),
            Err(err) => std::panic::resume_unwind(err),
        }
    }
}
