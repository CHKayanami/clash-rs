//! Association cancellation does not require a separate forwarding task.
#[cfg(feature = "tun")]
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
#[cfg(feature = "tun")]
use tokio_util::sync::CancellationToken;
use tokio::task::JoinHandle;

pub(super) enum Task {
    Spawned(JoinHandle<()>),
    #[cfg(feature = "tun")]
    Owned { cancel: CancellationToken, finished: Arc<AtomicBool> },
}
#[cfg(feature = "tun")]
pub(super) struct Owner {
    pub cancel: CancellationToken,
    finished: Arc<AtomicBool>,
}
#[cfg(feature = "tun")]
impl Drop for Owner {
    fn drop(&mut self) { self.finished.store(true, Ordering::Release); }
}
impl From<JoinHandle<()>> for Task {
    fn from(task: JoinHandle<()>) -> Self { Self::Spawned(task) }
}
impl Task {
    #[cfg(feature = "tun")]
    pub fn owned() -> (Self, Owner) {
        let cancel = CancellationToken::new();
        let finished = Arc::new(AtomicBool::new(false));
        (Self::Owned { cancel: cancel.clone(), finished: finished.clone() },
            Owner { cancel, finished })
    }
    #[cfg(feature = "tun")]
    pub fn completion_flag(&self) -> Option<Arc<AtomicBool>> {
        match self { Self::Owned { finished, .. } => Some(finished.clone()), _ => None }
    }
    pub fn abort(&self) {
        match self {
            Self::Spawned(task) => task.abort(),
            #[cfg(feature = "tun")]
            Self::Owned { cancel, .. } => cancel.cancel(),
        }
    }
    #[cfg(test)]
    pub fn is_finished(&self) -> bool {
        match self {
            Self::Spawned(task) => task.is_finished(),
            #[cfg(feature = "tun")]
            Self::Owned { finished, .. } => finished.load(Ordering::Acquire),
        }
    }
}

#[cfg(all(test, feature = "tun"))]
mod tests {
    use super::*;
    #[test]
    fn owner_drop_publishes_completion_without_retaining_the_session() {
        let (task, owner) = Task::owned();
        let finished = task.completion_flag().unwrap();
        assert!(!finished.load(Ordering::Acquire));
        drop(owner);
        assert!(finished.load(Ordering::Acquire));
        assert!(task.is_finished());
    }
}
