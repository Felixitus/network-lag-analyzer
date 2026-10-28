"""Stopping the capture process: SIGTERM must not wait for the next burst of the FRITZ!Box stream."""
import os
import signal
import socket
import sys
import threading
import time

import pytest

from backend.collectors import traffic


class W:
    running = True
    ring = None


def test_first_sigterm_interrupts_and_arms_the_deadline_a_second_one_does_not(monkeypatch):
    armed = []
    monkeypatch.setattr(traffic.signal, "alarm", lambda s: armed.append(s), raising=False)
    w = W()
    h = traffic.term_handler(w)
    with pytest.raises(traffic.Terminated):
        h(signal.SIGTERM, None)
    assert w.running is False and armed == [traffic.STOP_GRACE_S]
    h(signal.SIGTERM, None)                      # during the cleanup: ignored
    assert armed == [traffic.STOP_GRACE_S]
    assert not issubclass(traffic.Terminated, Exception)     # `except Exception` must not swallow it


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_sigterm_ends_a_blocking_read_at_once_and_the_cleanup_still_runs():
    a, b = socket.socketpair()                   # b never sends: a stalled capture stream
    a.settimeout(30)
    w = W()
    old = signal.signal(signal.SIGTERM, traffic.term_handler(w))
    cleaned = []
    t0 = time.monotonic()
    threading.Timer(0.3, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()
    try:
        with pytest.raises(traffic.Terminated):
            try:
                a.recv(65536)
            finally:
                cleaned.append(True)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGTERM, old)
        a.close()
        b.close()
    assert time.monotonic() - t0 < 3 and cleaned == [True]
