from pykdebugparser.kevent import Kevent


def test_turnstile_waitq_add_thread_priority_queue(traces_parser):
    events = [
        Kevent(timestamp=7476381345,
               data=(b'\xa1!\xae\xdb\x9818\x81\x91\x1d\x00\x00\x00\x00\x00\x00%\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9311246762178912673, 7569, 37, 0), tid=7569, debugid=890241028, eventid=890241028,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))[0]
    assert ret.turnstile == 0x81383198dbae21a1
    assert ret.tid == 7569
    assert ret.priority == 37


def test_turnstile_update_thread_promotion_locked(traces_parser):
    events = [
        Kevent(timestamp=7497627001,
               data=(b'a\xdc\xbf\xd9\x9818\x81\x1e\x1c\x00\x00\x00\x00\x00\x00/\x00\x00\x00\x00\x00\x00\x00%'
                     b'\x00\x00\x00\x00\x00\x00\x00'),
               values=(9311246762146520161, 7198, 47, 37), tid=7593, debugid=890241036, eventid=890241036,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))[0]
    assert ret.dst_turnstile == 0x81383198d9bfdc61
    assert ret.tid == 7198
    assert ret.priority == 47
    assert ret.thread_link_priority == 37


def test_turnstile_add_turnstile_promotion(traces_parser):
    events = [
        Kevent(timestamp=7476382413,
               data=(b'a\xb5o\xd8\x9818\x81!\xdd\xae\xdb\x9818\x81%\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9311246762124490081, 9311246762178960673, 37, 0), tid=6740, debugid=890241040, eventid=890241040,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))[0]
    assert ret.dst_turnstile == 0x81383198d86fb561
    assert ret.src_turnstile == 0x81383198dbaedd21
    assert ret.src_ts_priority == 37


def test_turnstile_remove_turnstile_promotion(traces_parser):
    events = [
        Kevent(timestamp=7476384288,
               data=(b'\xa1\xc9\xc1\xd9\x9818\x81!\xdd\xae\xdb\x9818\x81\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9311246762146646433, 9311246762178960673, 0, 0), tid=6740, debugid=890241044, eventid=890241044,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))[0]
    assert ret.dst_turnstile == 0x81383198d9c1c9a1
    assert ret.src_turnstile == 0x81383198dbaedd21


def test_turnstile_update_turnstile_promotion_locked(traces_parser):
    events = [
        Kevent(timestamp=7476376767,
               data=(b'A\xaa\x9f\xd7\x9818\x81!\xd4A\xd9\x9818\x81\x00\x00\x00\x00\x00\x00\x00\x00%'
                     b'\x00\x00\x00\x00\x00\x00\x00'),
               values=(9311246762110855745, 9311246762138260513, 0, 37), tid=7286, debugid=890241048, eventid=890241048,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))[0]
    assert ret.dst_turnstile == 0x81383198d79faa41
    assert ret.src_turnstile == 0x81383198d941d421
    assert ret.src_ts_priority == 0
    assert ret.src_turnstile_link_priority == 37


def test_thread_update_turnstile_promotion_locked(traces_parser):
    events = [
        Kevent(timestamp=7476383550,
               data=(b'T\x1a\x00\x00\x00\x00\x00\x00a\xb5o\xd8\x9818\x81\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00%\x00\x00\x00\x00\x00\x00\x00'),
               values=(6740, 9311246762124490081, 0, 37), tid=6740, debugid=890241060, eventid=890241060,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))[0]
    assert ret.tid == 6740
    assert ret.turnstile == 0x81383198d86fb561
    assert ret.turnstile_ts_priority == 0
    assert ret.turnstile_link_priority == 37


def test_thread_not_waiting_on_turnstile(traces_parser):
    events = [
        Kevent(timestamp=7476378853,
               data=(b'v\x1c\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(7286, 10, 0, 0), tid=7286, debugid=890241068, eventid=890241068, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))[0]
    assert ret.tid == 7286
    assert ret.turnstile_max_hop == 10
    assert ret.thread_hop == 0


def test_turnstile_recompute_priority_locked(traces_parser):
    events = [
        Kevent(timestamp=7476425345,
               data=(b'\x01\x93@\xd9\x9818\x81\x00\x00\x00\x00\x00\x00\x00\x00%\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9311246762138178305, 0, 37, 0), tid=7346, debugid=891289604, eventid=891289604,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))[0]
    assert ret.turnstile == 0x81383198d9409301
    assert ret.new_priority == 0
    assert ret.old_priority == 37


def test_thread_recompute_user_promotion_locked(traces_parser):
    events = [
        Kevent(timestamp=7476383893,
               data=(b'T\x1a\x00\x00\x00\x00\x00\x00%\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(6740, 37, 0, 0), tid=6740, debugid=891289608, eventid=891289608, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))[0]
    assert ret.tid == 0x1a54
    assert ret.user_promotion_basepri == 37
    assert ret.thread_user_promotion_basepri == 0
