use std::{io::{self, Read}, mem::{offset_of, size_of},
    os::{fd::AsRawFd, unix::net::UnixStream}, time::{Duration, Instant}};

use socket2::{Domain, Protocol, Socket, Type};
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub(super) struct Monitor {
    socket: Socket,
    wake: UnixStream,
}

impl Monitor {
    pub(super) fn new(wake: UnixStream) -> io::Result<Self> {
        let socket = Socket::new(Domain::from(libc::AF_ROUTE), Type::RAW,
            Some(Protocol::from(0)))?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket, wake })
    }

    pub(super) fn run(&self, token: &CancellationToken,
        mut refresh: impl FnMut() -> io::Result<()>) -> io::Result<()> {
        let mut buffer = [0u8; 16384];
        let mut refreshed = Instant::now();
        let mut dirty_since = None;
        let mut retry = false;
        while !token.is_cancelled() {
            let now = Instant::now();
            let deadline = dirty_since.map(|at: Instant| at + Duration::from_millis(100))
                .unwrap_or(refreshed + Duration::from_secs(if retry { 1 } else { 30 }));
            let timeout = deadline.saturating_duration_since(now).as_millis().max(1).min(i32::MAX as u128) as i32;
            let mut fds = [
                libc::pollfd { fd: self.socket.as_raw_fd(), events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: self.wake.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            ];
            // SAFETY: both descriptors remain owned by this worker for the
            // entire call. poll only writes the two live pollfd entries.
            let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted { continue; }
                return Err(error);
            }
            if token.is_cancelled() || fds[1].revents != 0 { break; }
            if fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(io::Error::other("macOS routing monitor socket failed"));
            }
            if fds[0].revents & libc::POLLIN != 0 {
                match (&self.socket).read(&mut buffer) {
                    Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                        "macOS routing socket closed")),
                    Ok(size) if network_changed(&buffer[..size]) => {
                        dirty_since.get_or_insert_with(Instant::now);
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
            if Instant::now() < deadline { continue; }
            refreshed = Instant::now();
            dirty_since = None;
            retry = false;
            if let Err(error) = refresh() {
                retry = true;
                warn!("failed to refresh macOS TUN routes: {error}");
            }
        }
        Ok(())
    }
}

fn network_changed(mut messages: &[u8]) -> bool {
    // Every Darwin routing message starts with native u16 length, u8 version,
    // u8 type. Read bytes rather than casting possibly unaligned kernel data.
    while messages.len() >= 4 {
        let length = u16::from_ne_bytes([messages[0], messages[1]]) as usize;
        if length < 4 || length > messages.len() { return false; }
        let kind = i32::from(messages[3]);
        if messages[2] != libc::RTM_VERSION as u8 {
            messages = &messages[length..];
            continue;
        }
        if matches!(kind, libc::RTM_ADD | libc::RTM_DELETE | libc::RTM_CHANGE) {
            if length < size_of::<libc::rt_msghdr>() { return false; }
            let word = |offset| i32::from_ne_bytes(messages[offset..offset + 4].try_into().unwrap());
            let flags = word(offset_of!(libc::rt_msghdr, rtm_flags));
            let error = word(offset_of!(libc::rt_msghdr, rtm_errno));
            if error == 0 && flags & (libc::RTF_WASCLONED | libc::RTF_LLINFO) == 0 {
                return true;
            }
        } else if matches!(kind, libc::RTM_NEWADDR | libc::RTM_DELADDR
            | libc::RTM_IFINFO | libc::RTM_IFINFO2) {
            return true;
        }
        // Ignore RTM_GET replies from our own route queries, otherwise every
        // reconciliation would trigger another reconciliation indefinitely.
        messages = &messages[length..];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, sync::mpsc, thread};

    #[test]
    fn cancellation_wakes_an_idle_monitor_without_waiting_for_reconciliation() {
        let (socket, _peer) = Socket::pair(Domain::UNIX, Type::DGRAM, None).unwrap();
        socket.set_nonblocking(true).unwrap();
        let (wake, mut sender) = UnixStream::pair().unwrap();
        let monitor = Monitor { socket, wake };
        let token = CancellationToken::new();
        let worker_token = token.clone();
        let (done, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = monitor.run(&worker_token, || panic!("idle monitor should not refresh"));
            done.send(result).unwrap();
        });
        thread::sleep(Duration::from_millis(10));
        token.cancel();
        sender.write_all(&[1]).unwrap();
        receiver.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn monitor_ignores_queries_and_handles_truncated_messages() {
        let message = |kind: u8| {
            let mut bytes = 4u16.to_ne_bytes().to_vec();
            bytes.extend([libc::RTM_VERSION as u8, kind]);
            bytes
        };
        let mut bytes = message(libc::RTM_GET as u8);
        assert!(!network_changed(&bytes));
        bytes.extend(message(libc::RTM_IFINFO as u8));
        assert!(network_changed(&bytes));
        assert!(!network_changed(&[0, 0, 0, 0]));
        assert!(!network_changed(&[255, 255, 0, libc::RTM_ADD as u8]));
    }

    #[test]
    fn neighbor_cache_and_failed_route_updates_do_not_refresh_the_network() {
        let mut message = vec![0; size_of::<libc::rt_msghdr>()];
        let length = message.len() as u16;
        message[..2].copy_from_slice(&length.to_ne_bytes());
        message[2] = libc::RTM_VERSION as u8;
        message[3] = libc::RTM_ADD as u8;
        let offset = offset_of!(libc::rt_msghdr, rtm_flags);
        message[offset..offset + 4].copy_from_slice(&libc::RTF_LLINFO.to_ne_bytes());
        assert!(!network_changed(&message));
        message[offset..offset + 4].copy_from_slice(&0i32.to_ne_bytes());
        assert!(network_changed(&message));
        let offset = offset_of!(libc::rt_msghdr, rtm_errno);
        message[offset..offset + 4].copy_from_slice(&libc::EEXIST.to_ne_bytes());
        assert!(!network_changed(&message));
    }
}
