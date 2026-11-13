use std::{env, fs::{self, OpenOptions}, io::{self, Write}, path::{Path, PathBuf}, process::Command,
    sync::atomic::{AtomicBool, Ordering}};

use tracing::warn;

use super::quote;

pub(super) struct Firewall {
    path: PathBuf,
    command: PathBuf,
    closed: AtomicBool,
}

impl Firewall {
    pub fn enable(device: &str, table: &str) -> io::Result<Option<Self>> {
        let Some(command) = env::var_os("PATH").and_then(|paths| {
            env::split_paths(&paths).map(|path| path.join("fw4")).find(|path| path.is_file())
        }) else { return Ok(None); };
        let dir = Path::new("/etc/nftables.d");
        if !dir.is_dir() {
            return Ok(None);
        }
        if !table_exists("fw4") {
            return Ok(None);
        }
        clean_stale_includes(dir, table, table_exists);
        let path = dir.join(format!("0-{table}-auto-redirect.nft"));
        Self::install(path, command, device, table).map(Some)
    }

    fn install(path: PathBuf, command: PathBuf, device: &str, table: &str) -> io::Result<Self> {
        let rules = Self::rules(device, table)?;
        // Ownership is exclusive: never replace a pre-existing include file.
        let mut file = OpenOptions::new().write(true).create_new(true).open(&path)?;
        if let Err(error) = file.write_all(rules.as_bytes()).and_then(|()| file.flush()) {
            drop(file);
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        drop(file);
        let guard = Self { path, command, closed: AtomicBool::new(false) };
        if let Err(error) = guard.reload() {
            let _ = fs::remove_file(&guard.path);
            guard.closed.store(true, Ordering::Release);
            return Err(error);
        }
        Ok(guard)
    }

    pub(super) fn rules(device: &str, table: &str) -> io::Result<String> {
        let device = quote(device)?;
        let mut rules = String::new();
        // fw4 includes this inside its own table. Extend the real chains;
        // accepting in a separate base chain cannot override fw4's drop policy.
        // Match fw4's hooks without assigning or changing their policies.
        for chain in ["input", "forward"] {
            rules.push_str(&format!("chain {chain} {{\n"));
            rules.push_str(&format!("    type filter hook {chain} priority filter;\n"));
            let directions: &[&str] = if chain == "input" { &["iifname"] } else { &["iifname", "oifname"] };
            for direction in directions {
                rules.push_str(&format!("    {direction} {device} counter accept comment \"!{table}: Accept TUN traffic\"\n"));
            }
            rules.push_str("}\n");
        }
        Ok(rules)
    }

    fn reload(&self) -> io::Result<()> {
        let output = Command::new(&self.command).arg("reload").output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!("TUN auto-redirect fw4 reload: {}",
                String::from_utf8_lossy(&output.stderr).trim())));
        }
        Ok(())
    }

    pub fn close(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.reload()?;
        self.closed.store(true, Ordering::Release);
        Ok(())
    }
}

impl Drop for Firewall {
    fn drop(&mut self) {
        if let Err(error) = self.close() { warn!("failed to remove TUN fw4 include: {error}"); }
    }
}

fn table_exists(table: &str) -> bool {
    Command::new("nft")
        .args(["list", "table", "inet", table])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn clean_stale_includes(dir: &Path, current_table: &str, is_active: impl Fn(&str) -> bool) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            warn!("failed to scan {} for stale TUN fw4 includes: {error}", dir.display());
            return;
        }
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else { continue; };
        let Some(table) = name
            .strip_prefix("0-")
            .and_then(|rest| rest.strip_suffix("-auto-redirect.nft"))
        else { continue; };
        if !table.starts_with("clash_tun_") || table == current_table {
            continue;
        }
        if !is_active(table) {
            if let Err(error) = fs::remove_file(entry.path())
                && error.kind() != io::ErrorKind::NotFound
            {
                warn!("failed to remove stale TUN fw4 include {}: {error}", entry.path().display());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    fn write_counting_command(dir: &Path, name: &str, counter: &Path, exit_code: i32) -> PathBuf {
        let script = dir.join(name);
        fs::write(
            &script,
            format!("#!/bin/sh\necho x >> \"{}\"\nexit {exit_code}\n", counter.display()),
        )
        .unwrap();
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
        script
    }

    #[test]
    fn auto_redirect_fw4_include_preserves_policy_and_cleans_up() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("auto-redirect.nft");
        let guard = Firewall::install(path.clone(), "/bin/true".into(), "tun0", "test").unwrap();
        let rules = fs::read_to_string(&path).unwrap();
        assert!(rules.contains("chain forward"));
        assert!(rules.contains("oifname \"tun0\" counter accept"));
        assert!(!rules.contains("policy"));
        assert!(rules.contains("hook forward priority filter"));
        assert!(Firewall::install(path.clone(), "/bin/true".into(), "tun1", "test").is_err());
        guard.close().unwrap();
        guard.close().unwrap();
        assert!(!path.exists());
        assert!(Firewall::install(path.clone(), "/bin/false".into(), "tun0", "test").is_err());
        assert!(!path.exists());
    }

    #[test]
    fn clean_stale_includes_removes_only_inactive_clash_tun_files() {
        let directory = tempdir().unwrap();
        let dir = directory.path();
        let stale = dir.join("0-clash_tun_100_0-auto-redirect.nft");
        let active = dir.join("0-clash_tun_200_0-auto-redirect.nft");
        let current = dir.join("0-clash_tun_300_0-auto-redirect.nft");
        let unrelated = dir.join("0-custom-auto-redirect.nft");
        for path in [&stale, &active, &current, &unrelated] {
            fs::write(path, "chain forward {}\n").unwrap();
        }
        clean_stale_includes(dir, "clash_tun_300_0", |table| table == "clash_tun_200_0");
        assert!(!stale.exists());
        assert!(active.exists());
        assert!(current.exists());
        assert!(unrelated.exists());
    }

    #[test]
    fn failed_reload_on_close_retries_until_reload_succeeds() {
        let directory = tempdir().unwrap();
        let dir = directory.path();
        let install_counter = dir.join("install_count");
        let fail_cmd = write_counting_command(dir, "fw4_fail", &install_counter, 1);
        let path = dir.join("auto-redirect.nft");
        assert!(Firewall::install(path.clone(), fail_cmd, "tun0", "test").is_err());
        assert!(!path.exists());
        assert_eq!(fs::read_to_string(&install_counter).unwrap().lines().count(), 1);

        let close_counter = dir.join("close_count");
        let ok_cmd = write_counting_command(dir, "fw4_ok", &close_counter, 0);
        let mut guard = Firewall::install(path.clone(), ok_cmd.clone(), "tun0", "test").unwrap();
        let fail_close_cmd = write_counting_command(dir, "fw4_fail_close", &close_counter, 1);
        guard.command = fail_close_cmd;
        assert!(guard.close().is_err());
        assert!(!path.exists());
        guard.command = ok_cmd;
        guard.close().unwrap();
        drop(guard);
        // 1 call from install(ok_cmd), 1 failed close, 1 retry close that succeeds, 0 extra on drop.
        assert_eq!(fs::read_to_string(&close_counter).unwrap().lines().count(), 3);
    }
}
