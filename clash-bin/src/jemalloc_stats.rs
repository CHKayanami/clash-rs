//! Only compiled for profiling builds that actually use the global Jemalloc.
use std::sync::Mutex;

use anyhow::{Context, Error, Result, anyhow};
use clash::app::memory::{JemallocStats, register_jemalloc_provider};
use tikv_jemalloc_ctl::{Access, AsName, epoch, stats};

// Serialize diagnostic refreshes; this does not lock application allocations.
static SNAPSHOT_LOCK: Mutex<()> = Mutex::new(());

pub fn register() -> Result<()> {
    register_jemalloc_provider(collect).map_err(Error::msg)
}

fn collect() -> Result<JemallocStats, String> {
    snapshot().map_err(|error| format!("{error:#}"))
}

fn snapshot() -> Result<JemallocStats> {
    let _guard = SNAPSHOT_LOCK.lock()
        .map_err(|_| anyhow!("jemalloc snapshot lock poisoned"))?;
    epoch::advance().context("refresh jemalloc epoch")?;
    let page: usize = b"arenas.page\0".name().read()?;
    // 4096 is jemalloc's MALLCTL_ARENAS_ALL: merged initialized-arena stats.
    // Both pdirty and pmuzzy have type size_t (usize), and count pages.
    let dirty_pages: usize = b"stats.arenas.4096.pdirty\0".name().read()?;
    let muzzy_pages: usize = b"stats.arenas.4096.pmuzzy\0".name().read()?;
    Ok(JemallocStats {
        allocated: stats::allocated::read()?,
        active: stats::active::read()?,
        resident: stats::resident::read()?,
        metadata: stats::metadata::read()?,
        dirty_bytes: dirty_pages.checked_mul(page).context("dirty bytes overflow")?,
        muzzy_bytes: muzzy_pages.checked_mul(page).context("muzzy bytes overflow")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clash::app::memory::memory_details;
    use std::hint::black_box;

    #[test]
    fn profiling_provider_reads_the_active_allocator() {
        let payload = vec![7_u8; 64 * 1024];
        black_box(&payload);
        register().unwrap();
        let details = memory_details();
        let stats = details.jemalloc.expect("registered allocator statistics");
        assert!(stats.allocated >= payload.len());
        let page: usize = b"arenas.page\0".name().read().unwrap();
        assert_eq!(stats.active % page, 0);
        assert_eq!(stats.dirty_bytes % page, 0);
        assert_eq!(stats.muzzy_bytes % page, 0);
        assert!(details.process.rss.is_some());
        assert!(details.errors.is_empty(), "{:?}", details.errors);
        drop(payload);
    }
}
