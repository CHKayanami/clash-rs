use clash_lib::{Config, Options, TokioRuntime, shutdown, start_scaffold};
use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
};

/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clash_start(
    config: *const c_char,
    log: *const c_char,
    cwd: *const c_char,
    multithread: c_int,
) -> *mut c_char {
    unsafe {
        if config.is_null() {
            return CString::new("Error: config pointer is null")
                .unwrap()
                .into_raw();
        }
        let config_str = match CStr::from_ptr(config).to_str() {
            Ok(s) => s.to_string(),
            Err(e) => {
                return CString::new(format!("Error: invalid UTF-8 in config: {e}"))
                    .unwrap()
                    .into_raw();
            }
        };
        let log_file = if log.is_null() {
            None
        } else {
            let s = CStr::from_ptr(log).to_str().unwrap_or_default().to_string();
            (!s.is_empty()).then_some(s)
        };
        let cwd = if cwd.is_null() {
            None
        } else {
            let s = CStr::from_ptr(cwd).to_str().unwrap_or_default().to_string();
            (!s.is_empty()).then_some(s)
        };

        let rt = if multithread != 0 {
            Some(TokioRuntime::MultiThread)
        } else {
            Some(TokioRuntime::SingleThread)
        };

        let options = Options {
            config: Config::Str(config_str),
            cwd,
            rt,
            log_file,
            enable_restart: false,
        };

        match start_scaffold(options) {
            Ok(_) => CString::new("").unwrap().into_raw(),
            Err(e) => CString::new(format!("Error: {e}")).unwrap().into_raw(),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn clash_shutdown() -> c_int {
    if shutdown() {
        1 // Success
    } else {
        0 // Failure
    }
}

/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unused_must_use)]
pub unsafe extern "C" fn clash_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        CString::from_raw(s);
    }
}

#[cfg(test)]
mod tests {
    use super::{clash_free_string, clash_shutdown, clash_start};
    use std::{
        ffi::{CStr, CString},
        fs,
        net::{TcpListener, TcpStream},
        ptr,
        thread,
        time::{Duration, Instant},
    };

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn wait_port(port: u16) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("port {port} did not open in time");
    }

    #[test]
    fn null_config_pointer_returns_error() {
        let msg = unsafe {
            let err_ptr = clash_start(ptr::null(), ptr::null(), ptr::null(), 0);
            let result = CStr::from_ptr(err_ptr).to_string_lossy().into_owned();
            clash_free_string(err_ptr);
            result
        };
        assert!(
            msg.contains("config pointer is null"),
            "expected null config error, got: {msg}"
        );
    }

    #[test]
    fn repeated_start_shutdown_start_succeeds_in_same_process() {
        let base_dir = std::env::temp_dir().join(format!(
            "clash-ffi-restart-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base_dir);
        fs::create_dir_all(&base_dir).unwrap();

        for cycle in 0..2 {
            let socks_port = free_port();
            let config = format!(
                "bind-address: 127.0.0.1\nsocks-port: {socks_port}\nmode: direct\nlog-level: info\ntun:\n  enable: false\n"
            );
            let log_name = format!("cycle-{cycle}.log");
            let c_config = CString::new(config).unwrap();
            let c_log = CString::new(log_name.as_str()).unwrap();
            let c_cwd = CString::new(base_dir.to_string_lossy().as_ref()).unwrap();

            let handle = thread::spawn(move || unsafe {
                let err_ptr = clash_start(
                    c_config.as_ptr(),
                    c_log.as_ptr(),
                    c_cwd.as_ptr(),
                    0,
                );
                let result = CStr::from_ptr(err_ptr).to_string_lossy().into_owned();
                clash_free_string(err_ptr);
                result
            });

            wait_port(socks_port);
            assert_eq!(clash_shutdown(), 1, "shutdown failed on cycle {cycle}");
            let err_msg = handle.join().unwrap();
            assert!(
                err_msg.is_empty(),
                "clash_start failed on cycle {cycle}: {err_msg}"
            );
            assert!(
                base_dir.join(&log_name).exists(),
                "expected log file for cycle {cycle}"
            );
        }

        let _ = fs::remove_dir_all(&base_dir);
    }
}
