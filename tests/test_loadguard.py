"""Load Guard: throttles the packet analysis only when the Pi or the capture reader is really behind."""
from backend.config import LoadGuardCfg
from backend.util.loadguard import LoadGuard


def guard(lag, busy):
    g = LoadGuard(LoadGuardCfg())
    g.capture_lag, g.capture_busy = lag, busy
    return g


def test_late_packets_from_the_fritzbox_with_an_idle_reader_do_not_throttle():
    # On the Pi: level 1 about once an hour at 2 % CPU, each time with a lag of ~2.0 s
    assert guard(2.1, 5.0).evaluate() == 0
    assert guard(6.0, 30.0).evaluate() == 0


def test_a_reader_that_cannot_keep_up_still_throttles():
    assert guard(2.1, 90.0).evaluate() == 1
    assert guard(6.0, 95.0).evaluate() == 2


def test_without_a_busy_share_the_lag_counts_as_before():
    assert guard(2.1, None).evaluate() == 1
