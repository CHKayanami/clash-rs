use std::{fs, io, path::PathBuf, sync::atomic::{AtomicBool, Ordering}};

use tracing::warn;

/// Relax only effective strict mode on the managed TUN interface. Linux takes
/// max(all, interface); leave an effectively disabled or loose mode unchanged.
pub(super) struct ReversePathFilter {
    path: PathBuf,
    previous: String,
    restored: AtomicBool,
}

impl ReversePathFilter {
    pub fn enable(device: &str) -> io::Result<Option<Self>> {
        // The caller validates the literal interface name before constructing
        // this procfs path, including rejection of '/', '.' and '..'.
        let path = PathBuf::from(format!("/proc/sys/net/ipv4/conf/{device}/rp_filter"));
        let previous = fs::read_to_string(&path)?;
        let all = fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter")?;
        let parse = |value: &str| -> io::Result<u8> {
            value.trim().parse::<u8>().ok().filter(|value| *value <= 2)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid IPv4 rp_filter value"))
        };
        if parse(&all)?.max(parse(&previous)?) != 1 { return Ok(None); }
        fs::write(&path, "2\n")?;
        Ok(Some(Self { path, previous, restored: AtomicBool::new(false) }))
    }

    pub fn restore(&self) -> io::Result<()> {
        if self.restored.load(Ordering::Acquire) { return Ok(()); }
        match fs::read_to_string(&self.path) {
            // Respect an administrator's change made while TUN was active.
            Ok(value) if value.trim() == "2" => fs::write(&self.path, &self.previous)?,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.restored.store(true, Ordering::Release);
        Ok(())
    }
}

impl Drop for ReversePathFilter {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            warn!("failed to restore TUN rp_filter at {}: {error}", self.path.display());
        }
    }
}
