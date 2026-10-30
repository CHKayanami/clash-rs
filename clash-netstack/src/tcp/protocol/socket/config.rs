// Derived from smoltcp; see ../LICENSE-0BSD.txt.
use super::*;

impl<'a> Socket<'a> {
    #[allow(unused_comparisons)] // small usize platforms always pass rx_capacity check
    /// Create a socket using the given buffers.
    pub fn new<T>(rx_buffer: T, tx_buffer: T) -> Socket<'a>
    where
        T: Into<SocketBuffer<'a>>,
    {
        let (rx_buffer, tx_buffer) = (rx_buffer.into(), tx_buffer.into());
        let rx_capacity = rx_buffer.capacity();

        // From RFC 1323:
        // [...] the above constraints imply that 2 * the max window size must be less
        // than 2**31 [...] Thus, the shift count must be limited to 14 (which allows
        // windows of 2**30 = 1 Gbyte).
        #[cfg(not(target_pointer_width = "16"))] // Prevent overflow
        if rx_capacity > (1 << 30) {
            panic!("receiving buffer too large, cannot exceed 1 GiB")
        }

        Socket {
            state: State::Closed,
            timer: Timer::new(),
            rtte: RttEstimator::default(),
            acknowledged_bytes: 0,
            assembler: Assembler::new(),
            tx_buffer,
            rx_buffer,
            rx_capacity_limit: rx_capacity,
            rx_fin_received: false,
            timeout: None,
            keep_alive: None,
            hop_limit: None,
            listen_endpoint: IpListenEndpoint::default(),
            tuple: None,
            local_seq_no: TcpSeqNumber::default(),
            remote_seq_no: TcpSeqNumber::default(),
            remote_last_seq: TcpSeqNumber::default(),
            remote_last_ack: None,
            remote_last_win_len: 0,
            remote_win_len: 0,
            remote_win_shift: Self::receive_window_shift(rx_capacity),
            remote_win_scale: None,
            remote_has_sack: false,
            remote_mss: DEFAULT_MSS,
            remote_last_ts: None,
            local_rx_last_ack: None,
            local_rx_last_seq: None,
            local_rx_dup_acks: 0,
            pending_fast_retransmit: false,
            ack_delay: Some(ACK_DELAY_DEFAULT),
            ack_delay_timer: AckDelayTimer::Idle,
            challenge_ack_timer: Instant::from_secs(0),
            nagle: true,
            tsval_generator: None,
            last_remote_tsval: 0,
            congestion_controller: congestion::AnyController::new(),

            rx_waker: WakerRegistration::new(),

            tx_waker: WakerRegistration::new(),

        }
    }

    /// Enable or disable TCP Timestamp.
    pub fn set_tsval_generator(&mut self, generator: Option<TcpTimestampGenerator>) {
        self.tsval_generator = generator;
    }

    /// Return whether TCP Timestamp is enabled.
    pub fn timestamp_enabled(&self) -> bool {
        self.tsval_generator.is_some()
    }

    /// Set an algorithm for congestion control.
    ///
    /// `CongestionControl::None` indicates that no congestion control is applied.
    /// Options `CongestionControl::Cubic` and `CongestionControl::Reno` are also available.
    ///
    /// `CongestionControl::Reno` is a classic congestion control algorithm valued for its simplicity.
    /// Despite having a lower algorithmic complexity than `Cubic`,
    /// it is less efficient in terms of bandwidth usage.
    ///
    /// `CongestionControl::Cubic` represents a modern congestion control algorithm designed to
    /// be more efficient and fair compared to `CongestionControl::Reno`.
    /// It is the default choice for Linux, Windows, and macOS.
    /// `CongestionControl::Cubic` relies on double precision (`f64`) floating point operations, which may cause issues in some contexts:
    /// * Small embedded processors (such as Cortex-M0, Cortex-M1, and Cortex-M3) do not have an FPU, and floating point operations consume significant amounts of CPU time and Flash space.
    /// * Interrupt handlers should almost always avoid floating-point operations.
    /// * Kernel-mode code on desktop processors usually avoids FPU operations to reduce the penalty of saving and restoring FPU registers.
    ///
    /// In all these cases, `CongestionControl::Reno` is a better choice of congestion control algorithm.
    pub fn set_congestion_control(&mut self, congestion_control: CongestionControl) {
        use congestion::*;

        self.congestion_controller = match congestion_control {
            CongestionControl::None => AnyController::None(no_control::NoControl),

            CongestionControl::Reno => AnyController::Reno(reno::Reno::new()),

            CongestionControl::Cubic => AnyController::Cubic(cubic::Cubic::new()),
        }
    }

    /// The engine is the sole protocol owner. Temporarily disarm its protocol
    /// wakes while servicing local I/O, then register them after all mutations.
    pub(crate) fn clear_wakers(&mut self) {
        self.rx_waker.clear();
        self.tx_waker.clear();
    }

    /// Return the current congestion control algorithm.
    pub fn congestion_control(&self) -> CongestionControl {
        use congestion::*;

        match self.congestion_controller {
            AnyController::None(_) => CongestionControl::None,

            AnyController::Reno(_) => CongestionControl::Reno,

            AnyController::Cubic(_) => CongestionControl::Cubic,
        }
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `recv` method calls, such as receiving data, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv` has
    ///   necessarily changed.

    pub fn register_recv_waker(&mut self, waker: &Waker) {
        self.rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `send` method calls, such as space becoming available in the transmit
    /// buffer, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send` has
    ///   necessarily changed.

    pub fn register_send_waker(&mut self, waker: &Waker) {
        self.tx_waker.register(waker)
    }

    /// Return the timeout duration.
    ///
    /// See also the [set_timeout](#method.set_timeout) method.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Return the ACK delay duration.
    ///
    /// See also the [set_ack_delay](#method.set_ack_delay) method.
    pub fn ack_delay(&self) -> Option<Duration> {
        self.ack_delay
    }

    /// Return the minimum retransmission timeout.
    ///
    /// See also the [set_min_rto](#method.set_min_rto) method.
    pub fn min_rto(&self) -> Duration {
        Duration::from_millis(self.rtte.min_rto as u64)
    }

    /// Return the retransmission timeout used before the first RTT measurement.
    ///
    /// See also the [set_initial_rto](#method.set_initial_rto) method.
    pub fn initial_rto(&self) -> Duration {
        Duration::from_millis(self.rtte.initial_rto as u64)
    }

    /// Return whether Nagle's Algorithm is enabled.
    ///
    /// See also the [set_nagle_enabled](#method.set_nagle_enabled) method.
    pub fn nagle_enabled(&self) -> bool {
        self.nagle
    }

    /// Pause sending of SYN|ACK packets.
    ///
    /// When this flag is set, the socket will get stuck in `SynReceived` state without sending
    /// any SYN|ACK packets back, until this flag is unset. This is useful for certain niche TCP
    /// proxy usecases.

    /// Return the current window field value, including scaling according to RFC 1323.
    ///
    /// Used in internal calculations as well as packet generation.
    #[inline]
    pub(super) fn scaled_window(&self) -> u16 {
        u16::try_from(self.rx_buffer.window() >> self.remote_win_shift).unwrap_or(u16::MAX)
    }

    /// Return the last window field value, including scaling according to RFC 1323.
    ///
    /// Used in internal calculations as well as packet generation.
    ///
    /// Unlike `remote_last_win_len`, we take into account new packets received (but not acknowledged)
    /// since the last window update and adjust the window length accordingly. This ensures a fair
    /// comparison between the last window length and the new window length we're going to
    /// advertise.
    #[inline]
    pub(super) fn last_scaled_window(&self) -> Option<u16> {
        let last_ack = self.remote_last_ack?;
        let next_ack = self.remote_seq_no + self.rx_buffer.len();

        let last_win = self.remote_last_win_len;
        let last_win_adjusted = last_win.saturating_sub(next_ack - last_ack);

        Some(u16::try_from(last_win_adjusted >> self.remote_win_shift).unwrap_or(u16::MAX))
    }

    /// Set the timeout duration.
    ///
    /// A socket with a timeout duration set will abort the connection if either of the following
    /// occurs:
    ///
    ///   * After a [connect](#method.connect) call, the remote endpoint does not respond within
    ///     the specified duration;
    ///   * After establishing a connection, there is data in the transmit buffer and the remote
    ///     endpoint exceeds the specified duration between any two packets it sends;
    ///   * After enabling [keep-alive](#method.set_keep_alive), the remote endpoint exceeds
    ///     the specified duration between any two packets it sends.
    pub fn set_timeout(&mut self, duration: Option<Duration>) {
        self.timeout = duration
    }

    /// Set the ACK delay duration.
    ///
    /// By default, the ACK delay is set to 10ms.
    pub fn set_ack_delay(&mut self, duration: Option<Duration>) {
        self.ack_delay = duration
    }

    /// Set the minimum retransmission timeout.
    ///
    /// The RTO computed from the RTT estimate is never allowed below this value.
    /// By default it is 1s, as recommended by RFC 6298 (2.4).
    ///
    /// On links whose round-trip time is far below a second, such as virtio, TAP, or a local
    /// Ethernet segment, this floor rather than the estimate determines the RTO, so a single lost
    /// segment costs a full second to recover.
    ///
    /// Setting this below the remote peer's delayed-ACK timer turns every delayed
    /// ACK into a spurious retransmission. [set_ack_delay](#method.set_ack_delay)
    /// delays ACKs by 10ms by default.
    ///
    /// The value is clamped to 1ms..=60s, and is preserved across [listen](#method.listen) and
    /// [connect](#method.connect). Raising it takes effect immediately.
    /// Lowering it takes effect at the next RTT measurement.
    pub fn set_min_rto(&mut self, duration: Duration) {
        self.rtte.min_rto = rto_millis(duration);
        self.rtte.rto = self.rtte.rto.max(self.rtte.min_rto);
    }

    /// Set the retransmission timeout used before the first RTT measurement.
    ///
    /// This is the RTO for the SYN, and for data sent before a round trip has been measured.
    /// By default it is 1s, as recommended by RFC 6298 (2.1).
    ///
    /// The value is clamped to 1ms..=60s, and is preserved across [listen](#method.listen) and
    /// [connect](#method.connect), so the usual place to call it is right after [new](#method.new).
    /// On a connected socket it takes effect only while no RTT measurement has been made and the
    /// retransmit timer has not backed off.
    pub fn set_initial_rto(&mut self, duration: Duration) {
        let initial_rto = rto_millis(duration);
        if !self.rtte.have_measurement && self.rtte.rto == self.rtte.initial_rto {
            self.rtte.rto = initial_rto;
        }
        self.rtte.initial_rto = initial_rto;
    }

    /// Enable or disable Nagle's Algorithm.
    ///
    /// Also known as "tinygram prevention". By default, it is enabled.
    /// Disabling it is equivalent to Linux's TCP_NODELAY flag.
    ///
    /// When enabled, Nagle's Algorithm prevents sending segments smaller than MSS if
    /// there is data in flight (sent but not acknowledged). In other words, it ensures
    /// at most only one segment smaller than MSS is in flight at a time.
    ///
    /// It ensures better network utilization by preventing sending many very small packets,
    /// at the cost of increased latency in some situations, particularly when the remote peer
    /// has ACK delay enabled.
    pub fn set_nagle_enabled(&mut self, enabled: bool) {
        self.nagle = enabled
    }

    /// Return the keep-alive interval.
    ///
    /// See also the [set_keep_alive](#method.set_keep_alive) method.
    pub fn keep_alive(&self) -> Option<Duration> {
        self.keep_alive
    }

    /// Set the keep-alive interval.
    ///
    /// An idle socket with a keep-alive interval set will transmit a "keep-alive ACK" packet
    /// every time it receives no communication during that interval. As a result, three things
    /// may happen:
    ///
    ///   * The remote endpoint is fine and answers with an ACK packet.
    ///   * The remote endpoint has rebooted and answers with an RST packet.
    ///   * The remote endpoint has crashed and does not answer.
    ///
    /// The keep-alive functionality together with the timeout functionality allows to react
    /// to these error conditions.
    pub fn set_keep_alive(&mut self, interval: Option<Duration>) {
        self.keep_alive = interval;
        if self.keep_alive.is_some() {
            // If the connection is idle and we've just set the option, it would not take effect
            // until the next packet, unless we wind up the timer explicitly.
            self.timer.set_keep_alive();
        }
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit
    }

    /// Return the listen endpoint
    #[inline]
    pub fn listen_endpoint(&self) -> IpListenEndpoint {
        self.listen_endpoint
    }

    /// Return the local endpoint, or None if not connected.
    #[inline]
    pub fn local_endpoint(&self) -> Option<IpEndpoint> {
        Some(self.tuple?.local)
    }

    /// Set the receive growth limit before listening or connecting.
    /// Window scaling will be negotiated for this limit while the actual
    /// advertised window remains bounded by the allocated receive buffer.
    /// The default limit is the initial receive capacity.
    ///
    /// # Panics
    /// Panics unless the socket is closed with no pending reset, and the limit
    /// is between the current receive capacity and 1 GiB (inclusive).
    pub fn set_receive_capacity_limit(&mut self, capacity: usize) {
        assert!(self.state == State::Closed && self.tuple.is_none());
        assert!(capacity >= self.rx_buffer.capacity());
        #[cfg(not(target_pointer_width = "16"))]
        assert!(capacity <= (1 << 30));
        self.rx_capacity_limit = capacity;
        self.remote_win_shift = Self::receive_window_shift(capacity);
    }

    /// Return the configured receive growth limit. Peers without window
    /// scaling still have an unscaled advertised window, regardless of this limit.
    pub fn receive_capacity_limit(&self) -> usize {
        self.rx_capacity_limit
    }

    pub(super) fn receive_window_shift(capacity: usize) -> u8 {
        let bits = mem::size_of::<usize>() * 8 - capacity.leading_zeros() as usize;
        bits.saturating_sub(16) as u8
    }

    /// Grow receive storage, preserving queued and out-of-order bytes.
    /// The replacement may be owned or borrowed; exclusive socket access
    /// ensures no slices into the previous storage can remain outstanding.
    /// Callers must poll the interface afterwards to publish window updates.
    /// Growth alone triggers an immediate update only when the scaled available
    /// window at least doubles the remaining previously advertised window.
    /// Smaller increases are advertised with subsequent outgoing segments.
    ///
    /// # Panics
    /// Panics if the replacement is smaller than current storage or exceeds
    /// the receive capacity limit configured before the handshake.
    pub fn grow_receive_buffer(&mut self, buffer: SocketBuffer<'a>) {
        assert!(buffer.capacity() >= self.rx_buffer.capacity());
        assert!(buffer.capacity() <= self.rx_capacity_limit);
        self.rx_buffer.grow(buffer);
    }

    /// Grow transmit storage, preserving queued bytes, including data still
    /// awaiting acknowledgment, without changing sequence numbers or timers.
    /// Callers must poll the interface after adding more application data.
    ///
    /// # Panics
    /// Panics if the replacement is smaller than current storage.
    pub fn grow_send_buffer(&mut self, buffer: SocketBuffer<'a>) {
        let increased = buffer.capacity() > self.tx_buffer.capacity();
        self.tx_buffer.grow(buffer);

        if increased {
            self.tx_waker.wake();
        }
    }

    /// Return the remote endpoint, or None if not connected.
    #[inline]
    pub fn remote_endpoint(&self) -> Option<IpEndpoint> {
        Some(self.tuple?.remote)
    }

    /// Return the connection state, in terms of the TCP state machine.
    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

    /// Useful delivery progress for buffer tuning, excluding SYN/FIN and duplicate ACKs.
    pub(crate) fn buffer_delivery(&self) -> (Duration, u64) {
        // RTT timestamps have millisecond precision. A measured sub-ms RTT
        // needs a one-tick floor, distinct from an unavailable estimate.
        let rtt = if self.rtte.have_measurement {
            self.rtte.smoothed_rtt().max(Duration::from_millis(1))
        } else {
            Duration::ZERO
        };
        (rtt, self.acknowledged_bytes)
    }

    pub(super) fn reset(&mut self) {
        self.state = State::Closed;
        self.timer = Timer::new();
        self.rtte.reset();
        self.acknowledged_bytes = 0;
        self.assembler = Assembler::new();
        self.tx_buffer.clear();
        self.rx_buffer.clear();
        self.rx_fin_received = false;
        self.listen_endpoint = IpListenEndpoint::default();
        self.tuple = None;
        self.local_seq_no = TcpSeqNumber::default();
        self.remote_seq_no = TcpSeqNumber::default();
        self.remote_last_seq = TcpSeqNumber::default();
        self.remote_last_ack = None;
        self.remote_last_win_len = 0;
        self.remote_win_len = 0;
        self.remote_win_scale = None;
        self.remote_win_shift = Self::receive_window_shift(self.rx_capacity_limit);
        self.remote_mss = DEFAULT_MSS;
        self.remote_last_ts = None;
        self.ack_delay_timer = AckDelayTimer::Idle;
        self.challenge_ack_timer = Instant::from_secs(0);

        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
    }
}
