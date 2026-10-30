// Derived from smoltcp; see ../LICENSE-0BSD.txt.
use super::*;

impl<'a> Socket<'a> {

    pub(super) fn timed_out(&self, timestamp: Instant) -> bool {
        match (self.remote_last_ts, self.timeout) {
            (Some(remote_last_ts), Some(timeout)) => timestamp >= remote_last_ts + timeout,
            (_, _) => false,
        }
    }

    pub(super) fn seq_to_transmit(&self, cx: &mut Context) -> bool {
        // Fast retransmits should always send, even if later congestion checks would disallow
        if self.pending_fast_retransmit && !self.tx_buffer.is_empty() {
            return true;
        }

        let ip_header_len = match self.tuple.unwrap().local.addr {

            IpAddress::Ipv4(_) => smoltcp::wire::IPV4_HEADER_LEN,

            IpAddress::Ipv6(_) => smoltcp::wire::IPV6_HEADER_LEN,
        };

        // The effective max segment size, taking into account the options and the local and remote limits.
        let options_len = if self.tsval_generator.is_some() {
            12
        } else {
            0
        };

        let local_mss = cx.ip_mtu() - ip_header_len - TCP_HEADER_LEN;
        let effective_mss = local_mss.min(self.remote_mss).saturating_sub(options_len);

        // Have we sent data that hasn't been ACKed yet?
        let data_in_flight = self.remote_last_seq != self.local_seq_no;

        // If we want to send a SYN and we haven't done so, do it!
        if matches!(self.state, State::SynSent | State::SynReceived) && !data_in_flight {
            return true;
        }

        // max sequence number we can send.
        let max_send_seq =
            self.local_seq_no + core::cmp::min(self.remote_win_len, self.tx_buffer.len());

        // Max amount of octets we can send.
        let capped_send_seq = if max_send_seq >= self.remote_last_seq {
            max_send_seq - self.remote_last_seq
        } else {
            0
        };

        // compare max bytes allowed by cwnd with max bytes allowed by remote
        let max_send = capped_send_seq.min(self.cwnd_remaining());

        // Can we send at least 1 octet?
        let mut can_send = max_send != 0;
        // Can we send at least 1 full segment?
        let can_send_full = max_send >= effective_mss;

        // Do we have to send a FIN?
        let want_fin = match self.state {
            State::FinWait1 => true,
            State::Closing => true,
            State::LastAck => true,
            _ => false,
        };

        // If we're applying the Nagle algorithm we don't want to send more
        // until one of:
        // * There's no data in flight
        // * We can send a full packet
        // * We have all the data we'll ever send (we're closing send)
        if self.nagle && data_in_flight && !can_send_full && !want_fin {
            can_send = false;
        }

        // Can we actually send the FIN? We can send it if:
        // 1. We have unsent data that fits in the remote window.
        // 2. We have no unsent data.
        // This condition matches only if #2, because #1 is already covered by can_data and we're ORing them.
        let can_fin = want_fin && self.remote_last_seq == self.local_seq_no + self.tx_buffer.len();

        can_send || can_fin
    }

    pub(super) fn delayed_ack_expired(&self, timestamp: Instant) -> bool {
        match self.ack_delay_timer {
            AckDelayTimer::Idle => true,
            AckDelayTimer::Waiting(t) => t <= timestamp,
            AckDelayTimer::Immediate => true,
        }
    }

    pub(super) fn ack_to_transmit(&self) -> bool {
        if let Some(remote_last_ack) = self.remote_last_ack {
            remote_last_ack < self.remote_seq_no + self.rx_buffer.len()
        } else {
            false
        }
    }

    /// Return whether to send ACK immediately due to the amount of unacknowledged data.
    ///
    /// RFC 9293 states "An ACK SHOULD be generated for at least every second full-sized segment or
    /// 2*RMSS bytes of new data (where RMSS is the MSS specified by the TCP endpoint receiving the
    /// segments to be acknowledged, or the default value if not specified) (SHLD-19)."
    ///
    /// Note that the RFC above only says "at least 2*RMSS bytes", which is not a hard requirement.
    /// In practice, we follow the Linux kernel's empirical value of sending an ACK for every RMSS
    /// byte of new data. For details, see
    /// <https://elixir.bootlin.com/linux/v6.11.4/source/net/ipv4/tcp_input.c#L5747>.
    pub(super) fn immediate_ack_to_transmit(&self) -> bool {
        if let Some(remote_last_ack) = self.remote_last_ack {
            remote_last_ack + self.remote_mss < self.remote_seq_no + self.rx_buffer.len()
        } else {
            false
        }
    }

    /// Return whether we should send ACK immediately due to significant window updates.
    ///
    /// ACKs with significant window updates should be sent immediately to let the sender know that
    /// more data can be sent. According to the Linux kernel implementation, "significant" means
    /// doubling the receive window. The Linux kernel implementation can be found at
    /// <https://elixir.bootlin.com/linux/v6.9.9/source/net/ipv4/tcp.c#L1472>.
    pub(super) fn window_to_update(&self) -> bool {
        match self.state {
            State::Established | State::FinWait1 | State::FinWait2 => {
                let new_win = self.scaled_window();
                if let Some(last_win) = self.last_scaled_window() {
                    new_win > 0 && new_win / 2 >= last_win
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, PacketMeta, (IpRepr, TcpRepr)) -> Result<(), E>,
    {
        if self.tuple.is_none() {
            return Ok(());
        }

        // NOTE(unwrap): we check tuple is not None above.
        let tuple = self.tuple.unwrap();

        // Check if the interface still has our source IP address.
        // If not (e.g. the interface's IP changed), reset the socket.
        // We use reset() instead of set_state(Closed) to avoid sending
        // an RST packet with the now-invalid source IP.
        if !cx.has_ip_addr(tuple.local.addr) {
            net_debug!("source IP address no longer available, closing socket");
            self.reset();
            return Ok(());
        }

        if self.remote_last_ts.is_none() {
            // We get here in exactly two cases:
            //  1) This socket just transitioned into SYN-SENT.
            //  2) This socket had an empty transmit buffer and some data was added there.
            // Both are similar in that the socket has been quiet for an indefinite
            // period of time, it isn't anymore, and the local endpoint is talking.
            // So, we start counting the timeout not from the last received packet
            // but from the first transmitted one.
            self.remote_last_ts = Some(cx.now());
        }

        self.congestion_controller
            .inner_mut()
            .pre_transmit(cx.now());

        // Check if any state needs to be changed because of a timer.
        if self.timed_out(cx.now()) {
            // If a timeout expires, we should abort the connection.
            net_debug!("timeout exceeded");
            self.set_state(State::Closed);
        } else if self.timer.should_retransmit(cx.now()) {
            if let Timer::Retransmit { .. } = self.timer {
                // If a retransmit timer expired, we should resend data starting at the last ACK.
                net_debug!("retransmitting after rto");

                // Inform the congestion controller that we're retransmitting and should enter the slow start state
                let in_flight = self.flight_size();
                self.congestion_controller
                    .inner_mut()
                    .on_rto(cx.now(), in_flight);

                // Rewind "last sequence number sent", as if we never
                // had sent them. This will cause all data in the queue
                // to be sent again.
                self.remote_last_seq = self.local_seq_no;

                // Inform RTTE, so that it can can handle RTO backoff
                self.rtte.on_rto();
            } else {
                // If a fast rentrasmit timer expired, we should resend only the earliest unAcked segment
                net_debug!("retransmitting for fast-retransmit");

                // Inform the congestion controller that we're doing a fast retransmit and should enter the fast recovery state
                let in_flight = self.flight_size();
                self.congestion_controller
                    .inner_mut()
                    .on_loss(cx.now(), in_flight);

                self.pending_fast_retransmit = true;
            }

            if self.remote_win_len == 0 && !self.tx_buffer.is_empty() {
                // Start a zero-window probe timer, it will fire in the future and always send something
                // so there is no infinite polling concern.
                let delay = self.rtte.retransmission_timeout();
                tcp_trace!("starting zero-window-probe timer for t+{}", delay);
                self.timer.set_for_zero_window_probe(cx.now(), delay);
            } else {
                // Clear the `should_retransmit` state. If we can't retransmit right
                // now for whatever reason, this avoids an infinite polling loop where
                // `poll_at` returns `Now` but `dispatch` can't actually do anything.
                self.timer.set_for_idle(cx.now(), self.keep_alive);
            }

            // Inform RTTE, so that it can avoid bogus measurements.
            self.rtte.on_retransmit();
        }

        // Decide whether we're sending a packet.
        if self.seq_to_transmit(cx) {
            // If we have data to transmit and it fits into partner's window, do it.
            tcp_trace!("outgoing segment will send data or flags");
        } else if self.ack_to_transmit() && self.delayed_ack_expired(cx.now()) {
            // If we have data to acknowledge, do it.
            tcp_trace!("outgoing segment will acknowledge");
        } else if self.window_to_update() {
            // If we have window length increase to advertise, do it.
            tcp_trace!("outgoing segment will update window");
        } else if self.state == State::Closed {
            // If we need to abort the connection, do it.
            tcp_trace!("outgoing segment will abort connection");
        } else if self.timer.should_keep_alive(cx.now()) {
            // If we need to transmit a keep-alive packet, do it.
            tcp_trace!("keep-alive timer expired");
        } else if self.timer.should_zero_window_probe(cx.now()) {
            tcp_trace!("sending zero-window probe");
        } else if self.timer.should_close(cx.now()) {
            // If we have spent enough time in the TIME-WAIT state, close the socket.
            tcp_trace!("TIME-WAIT timer expired");
            self.reset();
            return Ok(());
        } else {
            return Ok(());
        }

        // Construct the lowered IP representation.
        // We might need this to calculate the MSS, so do it early.
        let mut ip_repr = IpRepr::new(
            tuple.local.addr,
            tuple.remote.addr,
            IpProtocol::Tcp,
            0,
            self.hop_limit.unwrap_or(64),
        );

        // Construct the basic TCP representation, an empty ACK packet.
        // We'll adjust this to be more specific as needed.
        let mut repr = TcpRepr {
            src_port: tuple.local.port,
            dst_port: tuple.remote.port,
            control: TcpControl::None,
            seq_number: self.remote_last_seq,
            ack_number: Some(self.remote_seq_no + self.rx_buffer.len()),
            window_len: self.scaled_window(),
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: TcpTimestampRepr::generate_reply_with_tsval(
                self.tsval_generator,
                self.last_remote_tsval,
            ),
            payload: &[],
        };

        let mut is_zero_window_probe = false;

        let packet_meta = PacketMeta::default();

        match self.state {
            // We transmit an RST in the CLOSED state. If we ended up in the CLOSED state
            // with a specified endpoint, it means that the socket was aborted.
            State::Closed => {
                repr.control = TcpControl::Rst;
            }

            // We never transmit anything in the LISTEN state.
            State::Listen => return Ok(()),

            // We transmit a SYN in the SYN-SENT state.
            // We transmit a SYN|ACK in the SYN-RECEIVED state.
            State::SynSent | State::SynReceived => {
                repr.control = TcpControl::Syn;
                repr.seq_number = self.local_seq_no;
                // window len must NOT be scaled in SYNs.
                repr.window_len = u16::try_from(self.rx_buffer.window()).unwrap_or(u16::MAX);
                if self.state == State::SynSent {
                    repr.ack_number = None;
                    repr.window_scale = Some(self.remote_win_shift);
                    repr.sack_permitted = true;
                } else {
                    repr.sack_permitted = self.remote_has_sack;
                    repr.window_scale = self.remote_win_scale.map(|_| self.remote_win_shift);
                }
            }

            // We transmit data in all states where we may have data in the buffer,
            // or the transmit half of the connection is still open.
            State::Established
            | State::FinWait1
            | State::Closing
            | State::CloseWait
            | State::LastAck => {
                // Extract as much data as the remote side can receive in this packet
                // from the transmit buffer.

                // Maximum size we're allowed to send. This can be limited by 4 factors:
                // 1. remote window
                // 2. MSS the remote is willing to accept, probably determined by their MTU
                // 3. MSS we can send, determined by our MTU.
                // 4. Our congestion window
                let options_len = repr.header_len() - TCP_HEADER_LEN;
                let local_mss = cx.ip_mtu() - ip_repr.header_len() - TCP_HEADER_LEN;
                let effective_mss = local_mss.min(self.remote_mss).saturating_sub(options_len);

                let offset = if self.pending_fast_retransmit {
                    let size = effective_mss.min(self.tx_buffer.len());
                    repr.seq_number = self.local_seq_no;
                    repr.payload = self.tx_buffer.get_allocated(0, size);

                    0
                } else {
                    // Right edge of window, ie the max sequence number we're allowed to send.
                    let win_right_edge = self.local_seq_no + self.remote_win_len;

                    // Max amount of octets we're allowed to send according to the remote window.
                    let mut win_limit = if win_right_edge >= self.remote_last_seq {
                        win_right_edge - self.remote_last_seq
                    } else {
                        // This can happen if we've sent some data and later the remote side
                        // has shrunk its window so that data is no longer inside the window.
                        // This should be very rare and is strongly discouraged by the RFCs,
                        // but it does happen in practice.
                        // http://www.tcpipguide.com/free/t_TCPWindowManagementIssues.htm
                        0
                    };

                    // To send a zero-window-probe, force the window limit to at least 1 byte.
                    if win_limit == 0 && self.timer.should_zero_window_probe(cx.now()) {
                        win_limit = 1;
                        is_zero_window_probe = true;
                    }

                    // Maximum size we're allowed to send. This can be limited by 4 factors:
                    // 1. remote window
                    // 2. congestion window
                    // 3. MSS the remote is willing to accept, probably determined by their MTU
                    // 4. MSS we can send, determined by our MTU.
                    //
                    // If the device supports its offload, segmentation that is needed
                    // to comply with the latter two will be handled by the device based on the
                    // metadata we provide.

                    let device_limit = effective_mss;

                    let size = if is_zero_window_probe {
                        // Zero-window probes are exempt from the congestion window: they
                        // are sent precisely when normal transmission is impossible, and
                        // an empty segment elicits no reply, so capping the probe to a
                        // zero length would stall the connection if a window update from
                        // the remote got lost.
                        win_limit.min(device_limit)
                    } else {
                        win_limit.min(device_limit).min(self.cwnd_remaining())
                    };

                    let offset = self.flight_size();
                    repr.payload = self.tx_buffer.get_allocated(offset, size);

                    offset
                };

                // If we've sent everything we had in the buffer, follow it with the PSH or FIN
                // flags, depending on whether the transmit half of the connection is open.
                if offset + repr.payload.len() == self.tx_buffer.len() {
                    match self.state {
                        State::FinWait1 | State::LastAck | State::Closing => {
                            repr.control = TcpControl::Fin
                        }
                        State::Established | State::CloseWait if !repr.payload.is_empty() => {
                            repr.control = TcpControl::Psh
                        }
                        _ => (),
                    }
                }
            }

            // In FIN-WAIT-2 and TIME-WAIT states we may only transmit ACKs for incoming data or FIN
            State::FinWait2 | State::TimeWait => {}
        }

        // There might be more than one reason to send a packet. E.g. the keep-alive timer
        // has expired, and we also have data in transmit buffer. Since any packet that occupies
        // sequence space will elicit an ACK, we only need to send an explicit packet if we
        // couldn't fill the sequence space with anything.
        let is_keep_alive;
        if self.timer.should_keep_alive(cx.now()) && repr.is_empty() {
            repr.seq_number = repr.seq_number - 1;
            repr.payload = b"\x00"; // RFC 1122 says we should do this
            is_keep_alive = true;
        } else {
            is_keep_alive = false;
        }

        // Trace a summary of what will be sent.
        if is_keep_alive {
            tcp_trace!("sending a keep-alive");
        } else if !repr.payload.is_empty() {
            tcp_trace!(
                "tx buffer: sending {} octets at offset {}",
                repr.payload.len(),
                self.flight_size()
            );
        }
        if repr.control != TcpControl::None || repr.payload.is_empty() {
            let flags = match (repr.control, repr.ack_number) {
                (TcpControl::Syn, None) => "SYN",
                (TcpControl::Syn, Some(_)) => "SYN|ACK",
                (TcpControl::Fin, Some(_)) => "FIN|ACK",
                (TcpControl::Rst, Some(_)) => "RST|ACK",
                (TcpControl::Psh, Some(_)) => "PSH|ACK",
                (TcpControl::None, Some(_)) => "ACK",
                _ => "<unreachable>",
            };
            tcp_trace!("sending {}", flags);
        }

        if repr.control == TcpControl::Syn {
            // Fill the MSS option. See RFC 6691 for an explanation of this calculation.
            let max_segment_size = cx.ip_mtu() - ip_repr.header_len() - TCP_HEADER_LEN;
            repr.max_seg_size = Some(max_segment_size as u16);
        }

        // Actually send the packet. If this succeeds, it means the packet is in
        // the device buffer, and its transmission is imminent. If not, we might have
        // a number of problems, e.g. we need neighbor discovery.
        //
        // Bailing out if the packet isn't placed in the device buffer allows us
        // to not waste time waiting for the retransmit timer on packets that we know
        // for sure will not be successfully transmitted.
        ip_repr.set_payload_len(repr.buffer_len());
        emit(cx, packet_meta, (ip_repr, repr))?;

        // We have successfully emitted, if this was a fast retransmission it is not pending anymore
        self.pending_fast_retransmit = false;

        // We've sent something, whether useful data or a keep-alive packet, so rewind
        // the keep-alive timer.
        self.timer.rewind_keep_alive(cx.now(), self.keep_alive);

        // Reset delayed-ack timer
        match self.ack_delay_timer {
            AckDelayTimer::Idle => {}
            AckDelayTimer::Waiting(_) => {
                tcp_trace!("stop delayed ack timer")
            }
            AckDelayTimer::Immediate => {
                tcp_trace!("stop delayed ack timer (was force-expired)")
            }
        }
        self.ack_delay_timer = AckDelayTimer::Idle;

        // Leave the rest of the state intact if sending a zero-window probe.
        if is_zero_window_probe {
            self.timer.rewind_zero_window_probe(cx.now());
            return Ok(());
        }

        // Leave the rest of the state intact if sending a keep-alive packet, since those
        // carry a fake segment.
        if is_keep_alive {
            return Ok(());
        }

        // We've sent a packet successfully, so we can update the internal state now.
        // Use max() so a fast-retransmit segment (whose seq_number is local_seq_no, well
        // behind the current frontier) doesn't rewind the tracked "highest sent" sequence.
        self.remote_last_seq = self
            .remote_last_seq
            .max(repr.seq_number + repr.segment_len());
        self.remote_last_ack = repr.ack_number;
        self.remote_last_win_len = if repr.control == TcpControl::Syn {
            repr.window_len as usize
        } else {
            (repr.window_len as usize) << self.remote_win_shift
        };

        if repr.segment_len() > 0 {
            self.rtte
                .on_send(cx.now(), repr.seq_number + repr.segment_len());
            self.congestion_controller
                .inner_mut()
                .post_transmit(cx.now(), repr.segment_len());
        }

        if repr.segment_len() > 0 && !self.timer.is_retransmit() {
            // RFC 6298 (5.1) Every time a packet containing data is sent (including a
            // retransmission), if the timer is not running, start it running
            // so that it will expire after RTO seconds.
            let rto = self.rtte.retransmission_timeout();
            self.timer.set_for_retransmit(cx.now(), rto);
        }

        if self.state == State::Closed {
            // When aborting a connection, forget about it after sending a single RST packet.
            self.tuple = None;

            {
                // Wake tx now so that async users can wait for the RST to be sent
                self.tx_waker.wake();
            }
        }

        Ok(())
    }

    #[allow(clippy::if_same_then_else)]
    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        // The logic here mirrors the beginning of dispatch() closely.
        if self.tuple.is_none() {
            // No one to talk to, nothing to transmit.
            PollAt::Ingress
        } else if self.remote_last_ts.is_none() {
            // Socket stopped being quiet recently, we need to acquire a timestamp.
            PollAt::Now
        } else if self.state == State::Closed {
            // Socket was aborted, we have an RST packet to transmit.
            PollAt::Now
        } else if self.seq_to_transmit(cx) {
            // We have a data or flag packet to transmit.
            PollAt::Now
        } else if self.window_to_update() {
            // The receive window has been raised significantly.
            PollAt::Now
        } else {
            let want_ack = self.ack_to_transmit();

            let delayed_ack_poll_at = match (want_ack, self.ack_delay_timer) {
                (false, _) => PollAt::Ingress,
                (true, AckDelayTimer::Idle) => PollAt::Now,
                (true, AckDelayTimer::Waiting(t)) => PollAt::Time(t),
                (true, AckDelayTimer::Immediate) => PollAt::Now,
            };

            let timeout_poll_at = match (self.remote_last_ts, self.timeout) {
                // If we're transmitting or retransmitting data, we need to poll at the moment
                // when the timeout would expire.
                (Some(remote_last_ts), Some(timeout)) => PollAt::Time(remote_last_ts + timeout),
                // Otherwise we have no timeout.
                (_, _) => PollAt::Ingress,
            };

            // We wait for the earliest of our timers to fire.
            *[self.timer.poll_at(), timeout_poll_at, delayed_ack_poll_at]
                .iter()
                .min()
                .unwrap_or(&PollAt::Ingress)
        }
    }
}
