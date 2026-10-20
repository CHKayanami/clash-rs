//! On-demand diagnostics. The executable registers its actual allocator;
//! linking the library alone must not imply that jemalloc is in use.
use std::sync::OnceLock;

use chrono::Utc;
use serde::Serialize;

type JemallocProvider = fn() -> Result<JemallocStats, String>;
static JEMALLOC_PROVIDER: OnceLock<JemallocProvider> = OnceLock::new();

/// All sizes are bytes. These allocator counters are not OS RSS measurements.
#[derive(Debug, Serialize)]
pub struct JemallocStats {
    pub allocated: usize,
    pub active: usize,
    pub resident: usize,
    pub metadata: usize,
    pub dirty_bytes: usize,
    pub muzzy_bytes: usize,
}

/// Register only when jemalloc is the executable's active global allocator.
pub fn register_jemalloc_provider(
    provider: JemallocProvider,
) -> Result<(), &'static str> {
    JEMALLOC_PROVIDER.set(provider)
        .map_err(|_| "jemalloc statistics provider already registered")
}

#[derive(Debug, Default, Serialize)]
pub struct ProcessMemory {
    pub rss: Option<usize>,
    pub rss_anon: Option<usize>,
    pub rss_file: Option<usize>,
    pub rss_shmem: Option<usize>,
    pub threads: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct MemoryDetails {
    pub timestamp: String,
    pub process: ProcessMemory,
    pub jemalloc: Option<JemallocStats>,
    pub errors: Vec<String>,
}

pub fn memory_details() -> MemoryDetails {
    let mut snapshot = MemoryDetails {
        timestamp: Utc::now().to_rfc3339(),
        process: ProcessMemory::default(),
        jemalloc: None,
        errors: Vec::new(),
    };
    match JEMALLOC_PROVIDER.get() {
        Some(provider) => match provider() {
            Ok(stats) => snapshot.jemalloc = Some(stats),
            Err(error) => snapshot.errors.push(format!("jemalloc: {error}")),
        },
        None => snapshot.errors.push(
            "jemalloc statistics unavailable: no active provider registered".to_owned(),
        ),
    }
    match process_memory() {
        Ok(process) => snapshot.process = process,
        Err(error) => snapshot.errors.push(format!("process: {error}")),
    }
    snapshot
}

#[cfg(target_os = "linux")]
fn process_memory() -> Result<ProcessMemory, String> {
    use std::fs::read_to_string;

    let status = read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
    parse_linux_status(&status)
}

#[cfg(not(target_os = "linux"))]
fn process_memory() -> Result<ProcessMemory, String> {
    use memory_stats::memory_stats;

    let stats = memory_stats().ok_or("RSS measurement unavailable")?;
    Ok(ProcessMemory { rss: Some(stats.physical_mem), ..Default::default() })
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_status(status: &str) -> Result<ProcessMemory, String> {
    let mut process = ProcessMemory::default();
    for line in status.lines() {
        let Some((key, value)) = line.split_once(':') else { continue; };
        let (field, bytes) = match key {
            "VmRSS" => (&mut process.rss, true),
            "RssAnon" => (&mut process.rss_anon, true),
            "RssFile" => (&mut process.rss_file, true),
            "RssShmem" => (&mut process.rss_shmem, true),
            "Threads" => (&mut process.threads, false),
            _ => continue,
        };
        let mut parts = value.split_whitespace();
        let count = parts.next().and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| format!("invalid {key} in /proc/self/status"))?;
        if (bytes && parts.next() != Some("kB")) || parts.next().is_some() {
            return Err(format!("invalid units for {key} in /proc/self/status"));
        }
        *field = Some(if bytes {
            count.checked_mul(1024).ok_or_else(|| format!("{key} overflow"))?
        } else { count });
    }
    if process.rss.is_none() {
        return Err("VmRSS missing from /proc/self/status".to_owned());
    }
    Ok(process)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_status_converts_units_and_preserves_missing_fields() {
        let process = parse_linux_status(
            "Name:\tclash-rs\nVmRSS:\t42 kB\nRssAnon: 30 kB\n\
             RssFile: 12 kB\nRssShmem: 0 kB\nThreads: 5\n",
        ).unwrap();
        assert_eq!(process.rss, Some(42 * 1024));
        assert_eq!(process.rss_anon, Some(30 * 1024));
        assert_eq!(process.rss_file, Some(12 * 1024));
        assert_eq!(process.rss_shmem, Some(0));
        assert_eq!(process.threads, Some(5));
        let partial = parse_linux_status("VmRSS: 1 kB\n").unwrap();
        assert_eq!(partial.rss_anon, None);
        assert_eq!(partial.threads, None);
    }

    #[test]
    fn linux_status_rejects_invalid_measurements() {
        for status in ["", "VmRSS: x kB", "VmRSS: 1 MB", "VmRSS: 1 kB extra",
            "VmRSS: 1 kB\nThreads: 2 kB"] {
            assert!(parse_linux_status(status).is_err(), "{status}");
        }
        let overflow = format!("VmRSS: {} kB", usize::MAX);
        assert!(parse_linux_status(&overflow).is_err());
    }
}
