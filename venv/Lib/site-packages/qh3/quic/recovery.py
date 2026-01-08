from __future__ import annotations

import logging
import math
from typing import Any, Callable, Iterable

from .._hazmat import QuicPacketPacer, QuicRttMonitor, RangeSet
from .logger import QuicLoggerTrace
from .packet_builder import QuicDeliveryState, QuicSentPacket

# loss detection
K_PACKET_THRESHOLD = 3
K_GRANULARITY = 0.001  # seconds
K_TIME_THRESHOLD = 9 / 8
K_MICRO_SECOND = 0.000001
K_SECOND = 1.0

# congestion control
K_MAX_DATAGRAM_SIZE = 1280
K_INITIAL_WINDOW = 10 * K_MAX_DATAGRAM_SIZE
K_MINIMUM_WINDOW = 2 * K_MAX_DATAGRAM_SIZE
K_LOSS_REDUCTION_FACTOR = 0.5


class QuicPacketSpace:
    def __init__(self) -> None:
        self.ack_at: float | None = None
        self.ack_queue = RangeSet()
        self.discarded = False
        self.expected_packet_number = 0
        self.largest_received_packet = -1
        self.largest_received_time: float | None = None

        # sent packets and loss
        self.ack_eliciting_in_flight = 0
        self.largest_acked_packet = 0
        self.loss_time: float | None = None
        self.sent_packets: dict[int, QuicSentPacket] = {}


class QuicCongestionControl:
    """
    New Reno congestion control.
    """

    def __init__(self) -> None:
        self.bytes_in_flight = 0
        self.congestion_window = K_INITIAL_WINDOW
        self._congestion_recovery_start_time = 0.0
        self._congestion_stash = 0
        self._rtt_monitor = QuicRttMonitor()
        self.ssthresh: int | None = None

    def on_packet_acked(self, packet: QuicSentPacket) -> None:
        self.bytes_in_flight -= packet.sent_bytes

        # don't increase window in congestion recovery
        if packet.sent_time <= self._congestion_recovery_start_time:
            return

        if self.ssthresh is None or self.congestion_window < self.ssthresh:
            # slow start
            self.congestion_window += packet.sent_bytes
        else:
            # congestion avoidance
            self._congestion_stash += packet.sent_bytes
            count = self._congestion_stash // self.congestion_window
            if count:
                self._congestion_stash -= count * self.congestion_window
                self.congestion_window += count * K_MAX_DATAGRAM_SIZE

    def on_packet_sent(self, packet: QuicSentPacket) -> None:
        self.bytes_in_flight += packet.sent_bytes

    def on_packets_expired(self, packets: Iterable[QuicSentPacket]) -> None:
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes

    def on_packets_lost(self, packets: Iterable[QuicSentPacket], now: float) -> None:
        lost_largest_time = 0.0
        for packet in packets:
            self.bytes_in_flight -= packet.sent_bytes
            lost_largest_time = packet.sent_time

        # start a new congestion event if packet was sent after the
        # start of the previous congestion recovery period.
        if lost_largest_time > self._congestion_recovery_start_time:
            self._congestion_recovery_start_time = now
            self.congestion_window = max(
                int(self.congestion_window * K_LOSS_REDUCTION_FACTOR), K_MINIMUM_WINDOW
            )
            self.ssthresh = self.congestion_window

        # TODO : collapse congestion window if persistent congestion

    def on_rtt_measurement(self, latest_rtt: float, now: float) -> None:
        # check whether we should exit slow start
        if self.ssthresh is None and self._rtt_monitor.is_rtt_increasing(
            latest_rtt, now
        ):
            self.ssthresh = self.congestion_window


class QuicPacketRecovery:
    """
    Packet loss and congestion controller.
    """

    def __init__(
        self,
        initial_rtt: float,
        peer_completed_address_validation: bool,
        send_probe: Callable[[], None],
        logger: logging.LoggerAdapter | None = None,
        quic_logger: QuicLoggerTrace | None = None,
    ) -> None:
        self.max_ack_delay = 0.025
        self.peer_completed_address_validation = peer_completed_address_validation
        self.spaces: list[QuicPacketSpace] = []

        # callbacks
        self._logger = logger
        self._quic_logger = quic_logger
        self._send_probe = send_probe

        # loss detection
        self._pto_count = 0
        self._rtt_initial = initial_rtt
        self._rtt_initialized = False
        self._rtt_latest = 0.0
        self._rtt_min = math.inf
        self._rtt_smoothed = 0.0
        self._rtt_variance = 0.0
        self._time_of_last_sent_ack_eliciting_packet = 0.0

        # congestion control
        self._cc = QuicCongestionControl()
        self._pacer = QuicPacketPacer()

    @property
    def bytes_in_flight(self) -> int:
        return self._cc.bytes_in_flight

    @property
    def congestion_window(self) -> int:
        return self._cc.congestion_window

    def discard_space(self, space: QuicPacketSpace) -> None:
        assert space in self.spaces

        self._cc.on_packets_expired(
            filter(lambda x: x.in_flight, space.sent_packets.values())
        )
        space.sent_packets.clear()

        space.ack_at = None
        space.ack_eliciting_in_flight = 0
        space.loss_time = None

        # reset PTO count
        self._pto_count = 0

        if self._quic_logger is not None:
            self._log_metrics_updated()

    def get_loss_detection_time(self) -> float:
        # loss timer
        loss_space = self._get_loss_space()
        if loss_space is not None:
            return loss_space.loss_time

        # packet timer
        if (
            not self.peer_completed_address_validation
            or sum(space.ack_eliciting_in_flight for space in self.spaces) > 0
        ):
            timeout = self.get_probe_timeout() * (2**self._pto_count)
            return self._time_of_last_sent_ack_eliciting_packet + timeout

        return None

    def get_probe_timeout(self) -> float:
        if not self._rtt_initialized:
            return 2 * self._rtt_initial
        return (
            self._rtt_smoothed
            + max(4 * self._rtt_variance, K_GRANULARITY)
            + self.max_ack_delay
        )

    def on_ack_received(
        self,
        space: QuicPacketSpace,
        ack_rangeset: RangeSet,
        ack_delay: float,
        now: float,
    ) -> None:
        """
        Update metrics as the result of an ACK being received.
        """
        is_ack_eliciting = False
        largest_acked = ack_rangeset.bounds()[1] - 1
        largest_newly_acked = None
        largest_sent_time = None

        if largest_acked > space.largest_acked_packet:
            space.largest_acked_packet = largest_acked

        for packet_number in sorted(space.sent_packets.keys()):
            if packet_number > largest_acked:
                break
            if packet_number in ack_rangeset:
                # remove packet and update counters
                packet = space.sent_packets.pop(packet_number)
                if packet.is_ack_eliciting:
                    is_ack_eliciting = True
                    space.ack_eliciting_in_flight -= 1
                if packet.in_flight:
                    self._cc.on_packet_acked(packet)
                largest_newly_acked = packet_number
                largest_sent_time = packet.sent_time

                # trigger callbacks
                for handler, args in packet.delivery_handlers:
                    handler(QuicDeliveryState.ACKED, *args)

        # nothing to do if there are no newly acked packets
        if largest_newly_acked is None:
            return

        if largest_acked == largest_newly_acked and is_ack_eliciting:
            latest_rtt = now - largest_sent_time
            log_rtt = True

            # limit ACK delay to max_ack_delay
            ack_delay = min(ack_delay, self.max_ack_delay)

            # update RTT estimate, which cannot be < 1 ms
            self._rtt_latest = max(latest_rtt, 0.001)
            if self._rtt_latest < self._rtt_min:
                self._rtt_min = self._rtt_latest
            if self._rtt_latest > self._rtt_min + ack_delay:
                self._rtt_latest -= ack_delay

            if not self._rtt_initialized:
                self._rtt_initialized = True
                self._rtt_variance = latest_rtt / 2
                self._rtt_smoothed = latest_rtt
            else:
                self._rtt_variance = 3 / 4 * self._rtt_variance + 1 / 4 * abs(
                    self._rtt_min - self._rtt_latest
                )
                self._rtt_smoothed = (
                    7 / 8 * self._rtt_smoothed + 1 / 8 * self._rtt_latest
                )

            # inform congestion controller
            self._cc.on_rtt_measurement(latest_rtt, now=now)
            self._pacer.update_rate(
                congestion_window=self._cc.congestion_window,
                smoothed_rtt=self._rtt_smoothed,
            )

        else:
            log_rtt = False

        self._detect_loss(space, now=now)

        # reset PTO count
        self._pto_count = 0

        if self._quic_logger is not None:
            self._log_metrics_updated(log_rtt=log_rtt)

    def on_loss_detection_timeout(self, now: float) -> None:
        loss_space = self._get_loss_space()
        if loss_space is not None:
            self._detect_loss(loss_space, now=now)
        else:
            self._pto_count += 1
            self.reschedule_data(now=now)

    def on_packet_sent(self, packet: QuicSentPacket, space: QuicPacketSpace) -> None:
        space.sent_packets[packet.packet_number] = packet

        if packet.is_ack_eliciting:
            space.ack_eliciting_in_flight += 1
        if packet.in_flight:
            if packet.is_ack_eliciting:
                self._time_of_last_sent_ack_eliciting_packet = packet.sent_time

            # add packet to bytes in flight
            self._cc.on_packet_sent(packet)

            if self._quic_logger is not None:
                self._log_metrics_updated()

    def reschedule_data(self, now: float) -> None:
        """
        Schedule some data for retransmission.
        """
        # if there is any outstanding CRYPTO, retransmit it
        crypto_scheduled = False
        for space in self.spaces:
            packets = tuple(
                filter(lambda i: i.is_crypto_packet, space.sent_packets.values())
            )
            if packets:
                self._on_packets_lost(packets, space=space, now=now)
                crypto_scheduled = True
        if crypto_scheduled and self._logger is not None:
            self._logger.debug("Scheduled CRYPTO data for retransmission")

        # ensure an ACK-elliciting packet is sent
        self._send_probe()

    def _detect_loss(self, space: QuicPacketSpace, now: float) -> None:
        """
        Check whether any packets should be declared lost.
        """
        loss_delay = K_TIME_THRESHOLD * (
            max(self._rtt_latest, self._rtt_smoothed)
            if self._rtt_initialized
            else self._rtt_initial
        )
        packet_threshold = space.largest_acked_packet - K_PACKET_THRESHOLD
        time_threshold = now - loss_delay

        lost_packets = []
        space.loss_time = None
        for packet_number, packet in space.sent_packets.items():
            if packet_number > space.largest_acked_packet:
                break

            if packet_number <= packet_threshold or packet.sent_time <= time_threshold:
                lost_packets.append(packet)
            else:
                packet_loss_time = packet.sent_time + loss_delay
                if space.loss_time is None or space.loss_time > packet_loss_time:
                    space.loss_time = packet_loss_time

        self._on_packets_lost(lost_packets, space=space, now=now)

    def _get_loss_space(self) -> QuicPacketSpace | None:
        loss_space = None
        for space in self.spaces:
            if space.loss_time is not None and (
                loss_space is None or space.loss_time < loss_space.loss_time
            ):
                loss_space = space
        return loss_space

    def _log_metrics_updated(self, log_rtt=False) -> None:
        data: dict[str, Any] = {
            "bytes_in_flight": self._cc.bytes_in_flight,
            "cwnd": self._cc.congestion_window,
        }
        if self._cc.ssthresh is not None:
            data["ssthresh"] = self._cc.ssthresh

        if log_rtt:
            data.update(
                {
                    "latest_rtt": self._quic_logger.encode_time(self._rtt_latest),
                    "min_rtt": self._quic_logger.encode_time(self._rtt_min),
                    "smoothed_rtt": self._quic_logger.encode_time(self._rtt_smoothed),
                    "rtt_variance": self._quic_logger.encode_time(self._rtt_variance),
                }
            )

        self._quic_logger.log_event(
            category="recovery", event="metrics_updated", data=data
        )

    def _on_packets_lost(
        self, packets: Iterable[QuicSentPacket], space: QuicPacketSpace, now: float
    ) -> None:
        lost_packets_cc = []
        for packet in packets:
            del space.sent_packets[packet.packet_number]

            if packet.in_flight:
                lost_packets_cc.append(packet)

            if packet.is_ack_eliciting:
                space.ack_eliciting_in_flight -= 1

            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="recovery",
                    event="packet_lost",
                    data={
                        "type": self._quic_logger.packet_type(packet.packet_type),
                        "packet_number": packet.packet_number,
                    },
                )
                self._log_metrics_updated()

            # trigger callbacks
            for handler, args in packet.delivery_handlers:
                handler(QuicDeliveryState.LOST, *args)

        # inform congestion controller
        if lost_packets_cc:
            self._cc.on_packets_lost(lost_packets_cc, now=now)
            self._pacer.update_rate(
                congestion_window=self._cc.congestion_window,
                smoothed_rtt=self._rtt_smoothed,
            )
            if self._quic_logger is not None:
                self._log_metrics_updated()
