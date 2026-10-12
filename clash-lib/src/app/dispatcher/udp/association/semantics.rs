//! Mapping reuse and reply filtering are independent decisions.
//! Shared associations omit the destination from their key. Isolation keeps a
//! logical flow private when its transport or reply projection cannot be shared.
//! The relay admits unknown peers; address restoration does not grant admission.

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum IsolationReason {
    FixedTarget,
    UnresolvedFakeIp,
    UnknownSourcePort,
    ConflictingReplyAlias,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct FlowIsolation {
    id: u64,
    reason: IsolationReason,
}

impl FlowIsolation {
    pub(super) fn new(id: u64, reason: IsolationReason) -> Self {
        Self { id, reason }
    }

    pub(super) fn select(id: u64, explicit: Option<IsolationReason>,
        unresolved_fake: bool, source_port: u16,
    ) -> Option<Self> {
        let reason = explicit.or_else(|| {
            if unresolved_fake { Some(IsolationReason::UnresolvedFakeIp) }
            else if source_port == 0 { Some(IsolationReason::UnknownSourcePort) }
            else { None }
        });
        reason.map(|reason| Self::new(id, reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_is_shared_unless_a_specific_constraint_requires_isolation() {
        assert_eq!(FlowIsolation::select(1, None, false, 5000), None);
        assert_eq!(FlowIsolation::select(1, None, true, 5000),
            Some(FlowIsolation::new(1, IsolationReason::UnresolvedFakeIp)));
        assert_eq!(FlowIsolation::select(1, None, false, 0),
            Some(FlowIsolation::new(1, IsolationReason::UnknownSourcePort)));
        assert_eq!(FlowIsolation::select(1, Some(IsolationReason::ConflictingReplyAlias), true, 0),
            Some(FlowIsolation::new(1, IsolationReason::ConflictingReplyAlias)));
    }
}
