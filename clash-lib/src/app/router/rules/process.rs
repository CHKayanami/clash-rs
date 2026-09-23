use super::{RuleMatcher, contains_ignore_ascii_case};

pub struct Process {
    pub name: String,
    pub target: String,
    pub name_only: bool,
}

impl std::fmt::Display for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} process {}", self.target, self.name)
    }
}

impl RuleMatcher for Process {
    fn apply(&self, sess: &crate::session::Session) -> bool {
        // populated once per session by `Router::match_route`, off the async
        // runtime — see `should_resolve_process`
        let Some(proc) = sess.process_name.as_deref() else {
            return false;
        };

        tracing::debug!("matching process name: {} with {}", proc, self.name);

        if self.name_only {
            let file_name = proc
                .rsplit_once(['/', '\\'])
                .map(|(_, name)| name)
                .unwrap_or(proc);
            file_name.eq_ignore_ascii_case(&self.name)
        } else {
            contains_ignore_ascii_case(proc, &self.name)
        }
    }

    fn should_resolve_process(&self) -> bool {
        true
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.name.clone()
    }

    fn type_name(&self) -> &str {
        "Process"
    }
}

/// Look up the process owning the session's socket.
///
/// This walks the OS socket table and blocks, so it must not be called from the
/// async dispatch path directly — `Router::match_route` runs it on the blocking
/// pool, at most once per session.
pub fn find_process_name(sess: &crate::session::Session) -> Option<String> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        use crate::session::Network;

        sock2proc::find_process_name(
            Some(sess.source),
            sess.destination.clone().try_into_socket_addr(),
            match sess.network {
                Network::Tcp => sock2proc::NetworkProtocol::TCP,
                Network::Udp => sock2proc::NetworkProtocol::UDP,
            },
        )
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        tracing::info!("PROCESS-NAME not supported on this platform: {}", &sess);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;

    #[test]
    fn test_process_name_matching() {
        let matcher = Process {
            name: "curl".to_string(),
            target: "DIRECT".to_string(),
            name_only: true,
        };

        let mut sess = Session::default();

        // No process resolved yet
        assert!(!matcher.apply(&sess));

        // Exact match
        sess.process_name = Some("curl".to_string());
        assert!(matcher.apply(&sess));

        // Case-insensitive exact match
        sess.process_name = Some("CURL".to_string());
        assert!(matcher.apply(&sess));

        // Unix path
        sess.process_name = Some("/usr/bin/curl".to_string());
        assert!(matcher.apply(&sess));

        // Windows path
        sess.process_name = Some(r"C:\tools\curl".to_string());
        assert!(matcher.apply(&sess));

        // Non-matching process name
        sess.process_name = Some("/usr/bin/wget".to_string());
        assert!(!matcher.apply(&sess));

        // Process name containing "curl" as substring should not match name_only
        sess.process_name = Some("/usr/bin/curl-helper".to_string());
        assert!(!matcher.apply(&sess));
    }

    #[test]
    fn test_process_path_matching() {
        let matcher = Process {
            name: "/usr/bin/curl".to_string(),
            target: "DIRECT".to_string(),
            name_only: false,
        };

        let mut sess = Session::default();

        sess.process_name = Some("/usr/bin/curl".to_string());
        assert!(matcher.apply(&sess));

        sess.process_name = Some("/usr/local/bin/curl".to_string());
        assert!(!matcher.apply(&sess));

        // Substring / case-insensitive in path
        let sub_matcher = Process {
            name: "bin/curl".to_string(),
            target: "DIRECT".to_string(),
            name_only: false,
        };
        assert!(sub_matcher.apply(&sess));
    }
}
