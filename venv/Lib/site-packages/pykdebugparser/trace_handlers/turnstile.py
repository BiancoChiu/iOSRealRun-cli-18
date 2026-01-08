from dataclasses import dataclass
from enum import Enum
from typing import List


class TurnstileType(Enum):
    TURNSTILE_NONE = 0
    TURNSTILE_KERNEL_MUTEX = 1
    TURNSTILE_ULOCK = 2
    TURNSTILE_PTHREAD_MUTEX = 3
    TURNSTILE_SYNC_IPC = 4
    TURNSTILE_WORKLOOPS = 5
    TURNSTILE_WORKQS = 6
    TURNSTILE_KNOTE = 7
    TURNSTILE_SLEEP_INHERITOR = 8
    TURNSTILE_EPOCH_KERNEL = 9
    TURNSTILE_EPOCH_USER = 10
    TURNSTILE_TOTAL_TYPES = 11


@dataclass
class TurnstileWaitqAddThreadPriorityQueue:
    ktraces: List
    turnstile: int
    tid: int
    priority: int

    def __str__(self):
        return (f'turnstile_waitq_add_thread_priority_queue, turnstile: {hex(self.turnstile)}, tid: {self.tid},'
                f' priority: {self.priority}')


@dataclass
class ThreadRemovedFromTurnstileWaitq:
    ktraces: List
    turnstile: int
    tid: int

    def __str__(self):
        return f'thread_removed_from_turnstile_waitq, turnstile: {hex(self.turnstile)}, tid: {self.tid}'


@dataclass
class ThreadMovedInTurnstileWaitq:
    ktraces: List
    dst_turnstile: int
    tid: int
    priority: int
    thread_link_priority: int

    def __str__(self):
        return (f'turnstile_update_thread_promotion_locked, turnstile: {hex(self.dst_turnstile)}, tid: {self.tid},'
                f' priority: {self.priority}, link priority: {self.thread_link_priority}')


@dataclass
class TurnstileAddTurnstilePromotion:
    ktraces: List
    dst_turnstile: int
    src_turnstile: int
    src_ts_priority: int

    def __str__(self):
        return (f'turnstile_add_turnstile_promotion({hex(self.dst_turnstile)}, {hex(self.src_turnstile)}),'
                f' src_turnstile->ts_priority: {self.src_ts_priority}')


@dataclass
class TurnstileRemoveTurnstilePromotion:
    ktraces: List
    dst_turnstile: int
    src_turnstile: int

    def __str__(self):
        return f'turnstile_remove_turnstile_promotion({hex(self.dst_turnstile)}, {hex(self.src_turnstile)})'


@dataclass
class TurnstileUpdateTurnstilePromotionLocked:
    ktraces: List
    dst_turnstile: int
    src_turnstile: int
    src_ts_priority: int
    src_turnstile_link_priority: int

    def __str__(self):
        return (f'turnstile_update_turnstile_promotion_locked({hex(self.dst_turnstile)}, {hex(self.src_turnstile)}),'
                f' src_turnstile->ts_priority: {self.src_ts_priority}, '
                f'src_turnstile_link_priority: {self.src_turnstile_link_priority}')


@dataclass
class AddedFromThreadHeap:
    ktraces: List
    tid: int
    turnstile: int
    priority: int

    def __str__(self):
        return f'thread_add_turnstile_promotion({self.tid}, {hex(self.turnstile)}), priority: {self.priority}'


@dataclass
class RemovedFromThreadHeap:
    ktraces: List
    tid: int
    turnstile: int

    def __str__(self):
        return f'thread_remove_turnstile_promotion({self.tid}, {hex(self.turnstile)})'


@dataclass
class ThreadUpdateTurnstilePromotionLocked:
    ktraces: List
    tid: int
    turnstile: int
    turnstile_ts_priority: int
    turnstile_link_priority: int

    def __str__(self):
        return (f'thread_update_turnstile_promotion_locked, tid: {self.tid}, turnstile: {hex(self.turnstile)},'
                f' old_priority: {self.turnstile_ts_priority}, new_priority: {self.turnstile_link_priority}')


@dataclass
class ThreadNotWaitingOnTurnstile:
    ktraces: List
    tid: int
    turnstile_max_hop: int
    thread_hop: int

    def __str__(self):
        return (f'thread_not_waiting_on_turnstile, tid: {self.tid}, turnstile_max_hop: {self.turnstile_max_hop},'
                f' thread_hop: {self.thread_hop}')


@dataclass
class TurnstileRecomputePriorityLocked:
    ktraces: List
    turnstile: int
    new_priority: int
    old_priority: int

    def __str__(self):
        return (f'turnstile_recompute_priority_locked({hex(self.turnstile)}), new_priority: {self.new_priority},'
                f' old_priority: {self.old_priority}')


@dataclass
class ThreadRecomputeUserPromotionLocked:
    ktraces: List
    tid: int
    user_promotion_basepri: int
    thread_user_promotion_basepri: int

    def __str__(self):
        return (f'thread_recompute_user_promotion_locked, tid: {self.tid}, new_priority: {self.user_promotion_basepri},'
                f' old_priority: {self.thread_user_promotion_basepri}')


@dataclass
class TurnstilePrepare:
    ktraces: List
    turnstile: int
    proprietor: int
    type_: TurnstileType

    def __str__(self):
        return (f'turnstile_prepare, turnstile: {hex(self.turnstile)}, proprietor: {hex(self.proprietor)}, '
                f'type: {self.type_.name}')


@dataclass
class TurnstileComplete:
    ktraces: List
    turnstile: int
    proprietor: int
    type_: TurnstileType

    def __str__(self):
        return (f'turnstile_complete, turnstile: {hex(self.turnstile)}, proprietor: {hex(self.proprietor)}, '
                f'type: {self.type_.name}')


def handle_turnstile_thread_added_to_turnstile_waitq(parser, events):
    return TurnstileWaitqAddThreadPriorityQueue(events, *events[0].values[:3])


def handle_turnstile_thread_removed_from_turnstile_waitq(parser, events):
    return ThreadRemovedFromTurnstileWaitq(events, *events[0].values[:2])


def handle_turnstile_thread_moved_in_turnstile_waitq(parser, events):
    return ThreadMovedInTurnstileWaitq(events, *events[0].values)


def handle_turnstile_added_to_turnstile_heap(parser, events):
    return TurnstileAddTurnstilePromotion(events, *events[0].values[:3])


def handle_turnstile_removed_from_turnstile_heap(parser, events):
    return TurnstileRemoveTurnstilePromotion(events, *events[0].values[:2])


def handle_turnstile_moved_in_turnstile_heap(parser, events):
    return TurnstileUpdateTurnstilePromotionLocked(events, *events[0].values)


def handle_turnstile_added_from_thread_heap(parser, events):
    return AddedFromThreadHeap(events, *events[0].values[:3])


def handle_turnstile_removed_from_thread_heap(parser, events):
    return RemovedFromThreadHeap(events, *events[0].values[:2])


def handle_turnstile_moved_in_thread_heap(parser, events):
    return ThreadUpdateTurnstilePromotionLocked(events, *events[0].values)


def handle_thread_not_waiting_on_turnstile(parser, events):
    return ThreadNotWaitingOnTurnstile(events, *events[0].values[:3])


def handle_turnstile_priority_change(parser, events):
    return TurnstileRecomputePriorityLocked(events, *events[0].values[:3])


def handle_thread_user_promotion_change(parser, events):
    return ThreadRecomputeUserPromotionLocked(events, *events[0].values[:3])


def handle_turnstile_turnstile_prepare(parser, events):
    return TurnstilePrepare(events, *events[0].values[:2], TurnstileType(events[0].values[2]))


def handle_turnstile_turnstile_complete(parser, events):
    return TurnstileComplete(events, *events[0].values[:2], TurnstileType(events[0].values[2]))


handlers = {
    'TURNSTILE_thread_added_to_turnstile_waitq': handle_turnstile_thread_added_to_turnstile_waitq,
    'TURNSTILE_thread_removed_from_turnstile_waitq': handle_turnstile_thread_removed_from_turnstile_waitq,
    'TURNSTILE_thread_moved_in_turnstile_waitq': handle_turnstile_thread_moved_in_turnstile_waitq,
    'TURNSTILE_turnstile_added_to_turnstile_heap': handle_turnstile_added_to_turnstile_heap,
    'TURNSTILE_turnstile_removed_from_turnstile_heap': handle_turnstile_removed_from_turnstile_heap,
    'TURNSTILE_turnstile_moved_in_turnstile_heap': handle_turnstile_moved_in_turnstile_heap,
    'TURNSTILE_turnstile_added_to_thread_heap': handle_turnstile_added_from_thread_heap,
    'TURNSTILE_turnstile_removed_from_thread_heap': handle_turnstile_removed_from_thread_heap,
    'TURNSTILE_turnstile_moved_in_thread_heap': handle_turnstile_moved_in_thread_heap,
    'TURNSTILE_thread_not_waiting_on_turnstile': handle_thread_not_waiting_on_turnstile,
    'TURNSTILE_turnstile_priority_change': handle_turnstile_priority_change,
    'TURNSTILE_thread_user_promotion_change': handle_thread_user_promotion_change,
    'TURNSTILE_turnstile_prepare': handle_turnstile_turnstile_prepare,
    'TURNSTILE_turnstile_complete': handle_turnstile_turnstile_complete,
}
