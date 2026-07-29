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
            proc.eq_ignore_ascii_case(&self.name)
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
