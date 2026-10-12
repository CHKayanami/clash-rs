use std::{collections::HashMap, mem::take, sync::Arc};
use parking_lot::Mutex;
use tokio::sync::oneshot::Sender;

#[derive(Default)]
pub(crate) struct AssociationRegistry {
    closing: Mutex<HashMap<u64, Sender<()>>>,
}

pub(crate) struct AssociationGuard {
    id: u64,
    registry: Arc<AssociationRegistry>,
}

impl AssociationRegistry {
    pub(crate) fn register(self: &Arc<Self>, id: u64, close: Sender<()>) -> AssociationGuard {
        self.closing.lock().insert(id, close);
        AssociationGuard { id, registry: self.clone() }
    }

    pub(crate) fn close_all(&self) {
        let closing = take(&mut *self.closing.lock());
        for (_, close) in closing { let _ = close.send(()); }
    }
}

impl Drop for AssociationGuard {
    fn drop(&mut self) {
        self.registry.closing.lock().remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot::{self, error::TryRecvError};

    #[tokio::test]
    async fn close_all_and_guard_drop_release_lifetimes() {
        let registry = Arc::new(AssociationRegistry::default());
        let (tx, rx) = oneshot::channel();
        let first = registry.register(1, tx);
        drop(first);
        assert!(rx.await.is_err());
        let (tx, rx) = oneshot::channel();
        let second = registry.register(2, tx);
        registry.close_all();
        rx.await.unwrap();
        let (tx, mut rx) = oneshot::channel();
        let third = registry.register(3, tx);
        drop(second);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(registry.closing.lock().len(), 1);
        drop(third);
        assert!(registry.closing.lock().is_empty());
    }
}
