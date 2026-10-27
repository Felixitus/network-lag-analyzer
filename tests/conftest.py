import os
import random
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.correlation import CLOSE_AFTER, POST_SECONDS, Correlator  # noqa: E402
from backend.analysis.events import EventEngine  # noqa: E402
from backend.analysis.metrics import MetricsHub, TargetInfo  # noqa: E402
from backend.analysis.root_cause import Window  # noqa: E402
from backend.config import Thresholds  # noqa: E402
from backend import simulation as sim  # noqa: E402

# Addresses from the RFC 5737 documentation range - test data must never look like
# real targets and must never be contacted by accident.
TARGETS = {
    sim.GW_TID: {"address": "192.0.2.1", "name": "Router", "kind": "gateway"},
    sim.T1: {"address": "192.0.2.101", "name": "Reference 1", "kind": "internet"},
    sim.T2: {"address": "192.0.2.102", "name": "Reference 2", "kind": "internet"},
    sim.T3: {"address": "192.0.2.103", "name": "Reference 3", "kind": "internet"},
}
NAMES = {mac: name for mac, (ip, name) in sim.DEMO_DEVICES.items()}
IPS = {mac: ip for mac, (ip, name) in sim.DEMO_DEVICES.items()}


class Pipeline:
    """Hub + event engine + correlator as in production, but without network/DB."""

    def __init__(self, cap=(sim.CAP_DOWN, sim.CAP_UP), gaming=None):
        self.hub = MetricsHub(timeout=1.5)
        for tid, t in TARGETS.items():
            self.hub.set_target(TargetInfo(tid, t["address"], t["kind"], t["name"]))
        self.hub.dns_primary = "127.0.0.1"
        self.cap = cap
        self.gaming = gaming
        self.thresholds = Thresholds()
        ids = {"e": 0, "i": 0}

        def nid(k):
            ids[k] += 1
            return ids[k]
        self.events = []
        self.incidents = []
        self.engine = EventEngine(self.thresholds, lambda: self.cap, lambda: nid("e"),
                                  gaming_active_fn=lambda: self.gaming is not None)
        self.corr = Correlator(self.window, lambda: nid("i"), lambda inc, evs: self.incidents.append(inc))
        self.engine.on_start.append(self.corr.event_started)
        self.engine.on_start.append(self.events.append)
        self.engine.on_end.append(self.corr.event_ended)
        self.hub.subscribers.append(self._on_row)

    def label(self, mac):
        return {"mac": mac, "name": NAMES.get(mac, mac), "ip": IPS.get(mac)}

    def window(self, t0, t1):
        rows = self.hub.range(t0 - 30, t1 + 5)
        return Window(rows=rows, t0=int(t0), t1=int(t1), targets=TARGETS, cap_down=self.cap[0],
                      cap_up=self.cap[1], cap_source="config" if self.cap[0] else None,
                      thresholds=self.thresholds, device_label=self.label, gaming=self.gaming)

    def _on_row(self, row):
        self.engine.process(row)
        self.corr.tick(row["ts"])

    def run(self, scenario, seconds=30, pre=120, post=40, seed=1, gaming=False, start=1_700_000_000,
            traffic=True, ppt=1):
        rng = random.Random(seed)
        t = start
        for i in range(pre):
            s = sim.make_second("normal", 0, rng, gaming=gaming, probes_per_target=ppt)
            self._feed(t, s, traffic)
            t += 1
        self.scenario_start = t
        for k in range(seconds):
            s = sim.make_second(scenario, k, rng, onset=5, gaming=gaming, probes_per_target=ppt)
            self._feed(t, s, traffic)
            t += 1
        for i in range(post):
            s = sim.make_second("normal", 0, rng, gaming=gaming, probes_per_target=ppt)
            self._feed(t, s, traffic)
            t += 1
        self.hub.finalize_due(now=t + 10)
        self.corr.tick(t + CLOSE_AFTER + POST_SECONDS + 1)
        self.end = t
        return self

    def _feed(self, t, s, traffic):
        if not traffic:
            s.devices = {}
            s.glob = None
        for tid, samples in s.probes.items():
            for i, r in enumerate(samples):
                self.hub.add_probe(tid, t + i / max(1, len(samples)) + 0.01, r)
        for server, ms, status in s.dns:
            self.hub.add_dns(server, t + 0.5, ms, status)
        if s.glob is not None:
            self.hub.add_traffic_bin(t, s.devices, s.glob)


@pytest.fixture
def pipeline():
    return Pipeline
