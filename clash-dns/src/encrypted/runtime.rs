//! Own Quinn's background drivers so shutdown also waits for the UDP socket.
use std::{future::Future, io, net::UdpSocket, pin::Pin, sync::{Arc, Mutex}, time::Instant};
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, TokioRuntime};
use tokio::task::JoinHandle;

#[derive(Debug, Default)]
struct State {
    closed: bool,
    tasks: Vec<JoinHandle<()>>,
}

#[derive(Debug, Default)]
pub(crate) struct OwnedRuntime(Mutex<State>);

impl OwnedRuntime {
    pub fn abort(&self) {
        let mut state = self.0.lock().unwrap();
        state.closed = true;
        for task in &state.tasks { task.abort(); }
    }

    pub async fn shutdown(&self) {
        let tasks = {
            let mut state = self.0.lock().unwrap();
            state.closed = true;
            std::mem::take(&mut state.tasks)
        };
        for task in &tasks { task.abort(); }
        for task in tasks { let _ = task.await; }
    }
}

impl Runtime for OwnedRuntime {
    fn new_timer(&self, time: Instant) -> Pin<Box<dyn AsyncTimer>> {
        TokioRuntime.new_timer(time)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let mut state = self.0.lock().unwrap();
        if !state.closed {
            state.tasks.retain(|task| !task.is_finished());
            state.tasks.push(tokio::spawn(future));
        }
    }

    fn wrap_udp_socket(&self, socket: UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        TokioRuntime.wrap_udp_socket(socket)
    }

    fn now(&self) -> Instant { TokioRuntime.now() }
}
