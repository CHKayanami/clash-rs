use parking_lot::Mutex;
use tokio::sync::Notify;

#[derive(Clone, Copy, Eq, PartialEq)]
enum PoolState {
    Open,
    Closing,
    Closed,
}

struct AdmissionState {
    phase: PoolState,
    in_flight: usize,
    close_owner: bool,
}

pub struct AdmissionGate {
    state: Mutex<AdmissionState>,
    changed: Notify,
}

pub struct AdmissionPermit<'a> {
    gate: &'a AdmissionGate,
}

pub struct ClosePermit<'a> {
    gate: &'a AdmissionGate,
    armed: bool,
}

impl Default for AdmissionGate {
    fn default() -> Self {
        Self::new()
    }
}

impl AdmissionGate {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(AdmissionState {
                phase: PoolState::Open,
                in_flight: 0,
                close_owner: false,
            }),
            changed: Notify::new(),
        }
    }

    pub fn admit(&self) -> Option<AdmissionPermit<'_>> {
        let mut state = self.state.lock();
        if state.phase != PoolState::Open {
            return None;
        }
        state.in_flight = state.in_flight.checked_add(1)?;
        Some(AdmissionPermit { gate: self })
    }

    pub async fn acquire_close(&self) -> Option<ClosePermit<'_>> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self.state.lock();
                match state.phase {
                    PoolState::Open => {
                        state.phase = PoolState::Closing;
                        state.close_owner = true;
                        return Some(ClosePermit::new(self));
                    }
                    PoolState::Closing if !state.close_owner => {
                        state.close_owner = true;
                        return Some(ClosePermit::new(self));
                    }
                    PoolState::Closing => {}
                    PoolState::Closed => return None,
                };
            }
            changed.await;
        }
    }

    pub async fn wait_for_idle(&self) {
        self.wait_until(|state| state.in_flight == 0).await;
    }

    async fn wait_until(&self, condition: impl Fn(&AdmissionState) -> bool) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let ready = {
                let state = self.state.lock();
                condition(&state)
            };
            if ready {
                return;
            }
            changed.await;
        }
    }
}

impl<'a> ClosePermit<'a> {
    fn new(gate: &'a AdmissionGate) -> Self {
        Self { gate, armed: true }
    }

    pub fn complete(mut self) {
        {
            let mut state = self.gate.state.lock();
            state.phase = PoolState::Closed;
            state.close_owner = false;
        }
        self.armed = false;
        self.gate.changed.notify_waiters();
    }
}

impl Drop for ClosePermit<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        {
            let mut state = self.gate.state.lock();
            state.close_owner = false;
        }
        self.gate.changed.notify_waiters();
    }
}

impl Drop for AdmissionPermit<'_> {
    fn drop(&mut self) {
        let became_idle = {
            let mut state = self.gate.state.lock();
            let Some(remaining) = state.in_flight.checked_sub(1) else {
                return;
            };
            state.in_flight = remaining;
            remaining == 0
        };
        if became_idle {
            self.gate.changed.notify_waiters();
        }
    }
}
