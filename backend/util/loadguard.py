"""Load Guard: protects Pi-hole and measurement accuracy from overload caused by packet analysis.

Levels:
  0  normal                         full analysis
  1  CPU > cpu_high (10 s) or
     capture backlog > lag_high     no flow/retransmission analysis
  2  CPU > cpu_critical (5 s) or
     RAM low or backlog > lag_critical   sampling 1:4 (extrapolated, flagged)
  3  level 2 for 60 s               pause capture for 5 min
Stepping down only after 60 s below the thresholds (hysteresis).

The capture lag only counts as a backlog while the capture reader is busy most of the time.
The FRITZ!Box sends its stream in bursts, and packets arrive ~2 s old even when the reader is
idle: that delay is the box's, not ours, and switched the flow analysis off about once an hour
with the CPU at 2 %.
"""
from __future__ import annotations

import time
from collections import deque

import psutil

BUSY_BACKLOG_PCT = 50   # a reader waiting for the stream more than half the time is not behind


class LoadGuard:
    def __init__(self, cfg):
        self.cfg = cfg
        self.level = 0
        self._cpu: deque[tuple[float, float]] = deque(maxlen=120)
        self._since_level: float = time.time()
        self._calm_since: float | None = None
        self._lvl2_since: float | None = None
        self.last: dict = {}
        self.capture_lag = 0.0
        self.capture_busy: float | None = None   # share of wall time the reader spent parsing
        self.capture_pid: int | None = None
        self._proc = psutil.Process()
        self._cap_proc: psutil.Process | None = None
        psutil.cpu_percent(None)
        self._proc.cpu_percent(None)

    def set_capture_pid(self, pid: int | None) -> None:
        self.capture_pid = pid
        self._cap_proc = None
        if pid:
            try:
                self._cap_proc = psutil.Process(pid)
                self._cap_proc.cpu_percent(None)
            except psutil.Error:
                self._cap_proc = None

    def sample(self) -> dict:
        now = time.time()
        cpu = psutil.cpu_percent(None)
        self._cpu.append((now, cpu))
        vm = psutil.virtual_memory()
        temp = None
        try:
            temps = psutil.sensors_temperatures()
            for key in ("cpu_thermal", "coretemp", "soc_thermal", "k10temp"):
                if temps.get(key):
                    temp = temps[key][0].current
                    break
        except (AttributeError, OSError):
            pass
        own = self._proc.cpu_percent(None)
        cap = None
        if self._cap_proc is not None:
            try:
                cap = self._cap_proc.cpu_percent(None)
            except psutil.Error:
                cap = None
        try:
            rss = self._proc.memory_info().rss
        except psutil.Error:
            rss = None
        try:
            load1 = psutil.getloadavg()[0] if hasattr(psutil, "getloadavg") else None
        except (OSError, RuntimeError):
            # Windows without performance counters (dev mode): the load average is simply not available
            load1 = None
        self.last = {"ts": now, "cpu_pct": cpu, "mem_available_mb": round(vm.available / 1048576),
                     "mem_total_mb": round(vm.total / 1048576), "temp_c": temp, "app_cpu_pct": own,
                     "capture_cpu_pct": cap, "app_rss_mb": round(rss / 1048576, 1) if rss else None,
                     "load1": load1, "cpu_count": psutil.cpu_count(), "level": self.level,
                     "capture_lag_s": self.capture_lag, "capture_busy_pct": self.capture_busy}
        return self.last

    def _avg_cpu(self, seconds: float) -> float:
        now = time.time()
        vals = [c for t, c in self._cpu if now - t <= seconds]
        return sum(vals) / len(vals) if vals else 0.0

    def evaluate(self) -> int:
        """Computes the desired level (call once per second after sample())."""
        c = self.cfg
        now = time.time()
        mem_low = (self.last.get("mem_available_mb") or 1e9) < c.mem_min_available_mb
        # Unknown (an older capture process): counted as before
        backlog = self.capture_lag if self.capture_busy is None or self.capture_busy >= BUSY_BACKLOG_PCT else 0.0
        crit = self._avg_cpu(5) > c.cpu_critical or mem_low or backlog > c.capture_lag_critical
        high = self._avg_cpu(10) > c.cpu_high or backlog > c.capture_lag_high
        want = 2 if crit else 1 if high else 0
        if want == 2:
            self._lvl2_since = self._lvl2_since or now
            if now - self._lvl2_since >= 60:
                want = 3
        else:
            self._lvl2_since = None
        if want > self.level:
            self.level = want
            self._calm_since = None
        elif want < self.level:
            self._calm_since = self._calm_since or now
            if now - self._calm_since >= 60:
                self.level = want if self.level != 3 else 0
                self._calm_since = None
        else:
            self._calm_since = None
        if self.level == 3:
            # The pause is applied in the capture process; re-evaluate afterwards
            self._lvl2_since = None
        self.last["level"] = self.level
        return self.level
