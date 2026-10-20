"""Jitter, Packet Loss, Sekunden-Assembler, Traffic-Aggregation."""
from backend.analysis.metrics import MetricsHub, TargetInfo, jitter_ms, loss_percent


def test_jitter_mean_abs_diff():
    assert jitter_ms([10, 12, 10, 14]) == (2 + 2 + 4) / 3


def test_jitter_skips_lost_and_needs_two_values():
    assert jitter_ms([10, None, 20]) == 10
    assert jitter_ms([None, 5]) is None
    assert jitter_ms([]) is None


def test_loss_percent():
    assert loss_percent(10, 1) == 10.0
    assert loss_percent(0, 0) is None      # nothing measured ≠ 0 % loss


def _hub():
    h = MetricsHub(timeout=1.5)
    h.set_target(TargetInfo(1, "192.0.2.1", "gateway"))
    h.set_target(TargetInfo(2, "192.0.2.101", "internet"))
    h.set_target(TargetInfo(3, "192.0.2.102", "internet"))
    h.set_target(TargetInfo(4, "192.0.2.103", "internet"))
    return h


def test_second_row_median_loss_and_gateway():
    h = _hub()
    t = 1_700_000_000
    h.add_probe(1, t + 0.1, 1.2)
    h.add_probe(2, t + 0.1, 10.0)
    h.add_probe(3, t + 0.1, 20.0)
    h.add_probe(4, t + 0.1, None)
    rows = h.finalize_due(now=t + 10)
    r = rows[0]
    assert r["rtt_avg"] == 15.0            # median of the reachable internet targets
    assert r["rtt_min"] == 10.0 and r["rtt_max"] == 20.0
    assert r["probes"] == 3 and r["lost"] == 1
    assert round(r["loss_pct"], 2) == 33.33
    assert r["gw_rtt"] == 1.2 and r["gw_lost"] == 0


def test_second_not_finalized_before_timeout():
    h = _hub()
    t = 1_700_000_000
    h.add_probe(2, t + 0.5, 12.0)
    assert h.finalize_due(now=t + 2.0) == []   # probes might still be in flight
    assert len(h.finalize_due(now=t + 3.0)) == 1


def test_no_probes_means_none_not_zero():
    h = _hub()
    t = 1_700_000_000
    h.add_probe(2, t, 12.0)
    rows = h.finalize_due(now=t + 10)
    empty = [r for r in rows if r["probes"] == 0]
    assert empty and all(r["rtt_avg"] is None and r["loss_pct"] is None for r in empty)
    assert all(r["down_bps"] is None and r["traffic_src"] is None for r in rows)


def test_loss_windows():
    h = _hub()
    t = 1_700_000_000
    for i in range(60):
        for tid in (2, 3, 4):
            h.add_probe(tid, t + i, None if (i >= 55 and tid == 2) else 15.0)
    h.finalize_due(now=t + 61.8)
    w = h.loss_windows()
    assert w["5s"] == round(100 * 5 / 15, 2)
    assert w["60s"] == round(100 * 5 / 180, 2)


def test_traffic_bins_become_bps_and_capture_source():
    h = _hub()
    t = 1_700_000_000
    h.add_probe(2, t, 10.0)
    h.add_traffic_bin(t, {"aa:bb:cc:dd:ee:01": [1000, 500, 1, 1, 0, 0, 0]},
                      {"wan_rx": 1000, "wan_tx": 500, "tcp_segs": 10, "retrans_down": 1, "retrans_up": 0})
    r = h.finalize_due(now=t + 10)[0]
    assert r["down_bps"] == 8000 and r["up_bps"] == 4000
    assert r["traffic_src"] == "capture" and r["retrans"] == 1


def test_tr064_rate_fills_seconds_without_capture():
    h = _hub()
    t = 1_700_000_000
    for i in range(4):
        h.add_probe(2, t + i, 10.0)
    h.add_wan_rate(t + 1.5, 50e6, 5e6)
    h.add_wan_rate(t + 3.5, 60e6, 6e6)
    rows = {r["ts"]: r for r in h.finalize_due(now=t + 10)}
    assert rows[t + 1]["traffic_src"] == "tr064" and rows[t + 1]["down_bps"] == 50e6
    assert rows[t + 3]["down_bps"] == 60e6
    assert rows[t + 1]["devices"] == {}    # TR-064 delivers no per-device values


def _bin(n=1000):
    return {"aa:bb:cc:dd:ee:01": [n, n // 2, 1, 1, 0, 0, 0]}, {"wan_rx": n, "wan_tx": n // 2, "tcp_segs": 5,
                                                               "retrans_down": 0, "retrans_up": 0}


def test_buffered_capture_stream_does_not_lose_traffic():
    """The FRITZ!Box delivers the capture in bursts - seconds must still not be finalized without traffic."""
    h = _hub()
    t = 1_700_000_000
    rows = []
    for i in range(40):
        sec = t + i
        for tid in (1, 2, 3, 4):
            h.add_probe(tid, sec + 0.1, 12.0)
        now = sec + 1.0
        if i % 3 == 2:                      # only every 3 s a burst with 3 bins arrives
            for s in range(sec - 2, sec + 1):
                devices, glob = _bin()
                h.add_traffic_bin(s, devices, glob)
        rows += h.finalize_due(now=now)
    measured = [r for r in rows if r["probes"] > 0]
    assert len(measured) >= 30
    missing = [r for r in measured if r["traffic_src"] is None]
    assert not missing, f"{len(missing)} seconds without traffic data despite a running capture"
    assert all(r["down_bps"] == 8000 for r in measured)


def test_traffic_grace_is_bounded_when_capture_stalls():
    """If the capture hangs, the evaluation must not wait forever."""
    h = _hub()
    h.traffic_grace = 4.0
    t = 1_700_000_000
    devices, glob = _bin()
    h.add_traffic_bin(t, devices, glob)
    for i in range(1, 8):
        h.add_probe(2, t + i + 0.1, 12.0)
    rows = h.finalize_due(now=t + 9)        # no bin since t
    assert rows, "evaluation stalled"
    assert rows[-1]["ts"] >= t + 4
    assert rows[-1]["traffic_src"] is None  # honest: no traffic measured


def test_late_bin_patches_row_and_notifies():
    h = _hub()
    h.traffic_grace = 1.0
    t = 1_700_000_000
    patched = []
    h.patch_subscribers.append(patched.append)
    h.add_probe(2, t + 0.1, 12.0)
    h.add_traffic_bin(t - 1, *_bin())       # activates the capture state
    h.finalize_due(now=t + 4)
    row_t = [r for r in h.ring if r["ts"] == t][0]
    assert row_t["traffic_src"] is None
    devices, glob = _bin(4000)
    h.add_traffic_bin(t, devices, glob)     # bin arrives too late
    assert h.late_traffic == 1
    assert patched and patched[0]["ts"] == t
    row = [r for r in h.ring if r["ts"] == t][0]
    assert row["traffic_src"] == "capture" and row["down_bps"] == 32000 and row["late"] is True
    assert row["devices"] == devices


def test_capture_bin_overrides_tr064_total():
    """TR-064 only delivers totals; if the capture arrives later, it replaces them."""
    h = _hub()
    t = 1_700_000_000
    h.add_probe(2, t + 0.1, 12.0)
    h.add_traffic_bin(t - 1, *_bin())            # capture is active
    h.add_wan_rate(t + 0.5, 50e6, 5e6)
    h.traffic_grace = 1.0
    h.finalize_due(now=t + 4)
    row = [r for r in h.ring if r["ts"] == t][0]
    assert row["traffic_src"] == "tr064" and row["down_bps"] == 50e6 and row["devices"] == {}
    devices, glob = _bin(4000)
    h.add_traffic_bin(t, devices, glob)          # capture arrives late
    assert row["traffic_src"] == "capture" and row["down_bps"] == 32000
    assert row["devices"] == devices


def test_dead_target_is_excluded_from_packet_loss():
    """A target that never answers (e.g. ICMP blocked) must not produce permanent packet loss."""
    h = _hub()
    t = 1_700_000_000
    rows = []
    for i in range(90):
        h.add_probe(2, t + i + 0.1, 15.0)
        h.add_probe(3, t + i + 0.1, 18.0)
        h.add_probe(4, t + i + 0.1, None)        # target 4 never answers
        rows += h.finalize_due(now=t + i + 3.0)
    early = [r for r in rows if r["ts"] < t + 20]
    late = [r for r in rows if r["ts"] > t + 60]
    assert all(abs(r["loss_pct"] - 100 * 1 / 3) < 0.1 for r in early), "at first the loss is correct"
    assert all(r["loss_pct"] == 0.0 for r in late), "after the grace period no loss may be counted any more"
    assert all(r["probes"] == 2 for r in late)
    health = {x["address"]: x for x in h.target_health()}
    assert health["192.0.2.103"]["unreachable"] is True
    assert health["192.0.2.101"]["unreachable"] is False
    assert all(r["rtt_avg"] is not None for r in late)


def test_total_outage_is_still_packet_loss():
    """If ALL targets fail, that is a real outage and keeps counting as loss."""
    h = _hub()
    t = 1_700_000_000
    rows = []
    for i in range(90):
        for tid in (2, 3, 4):
            h.add_probe(tid, t + i + 0.1, 15.0 if i < 20 else None)
        rows += h.finalize_due(now=t + i + 3.0)
    late = [r for r in rows if r["ts"] > t + 60]
    assert all(r["loss_pct"] == 100.0 and r["probes"] == 3 for r in late)
    assert not any(x["unreachable"] for x in h.target_health())


def test_dead_target_counts_again_after_recovery():
    h = _hub()
    t = 1_700_000_000
    for i in range(60):
        h.add_probe(2, t + i + 0.1, 15.0)
        h.add_probe(3, t + i + 0.1, 15.0)
        h.add_probe(4, t + i + 0.1, None)
        h.finalize_due(now=t + i + 3.0)
    assert [x for x in h.target_health() if x["unreachable"]]
    rows = []
    for i in range(60, 80):                      # target 4 answers again
        h.add_probe(2, t + i + 0.1, 15.0)
        h.add_probe(3, t + i + 0.1, 15.0)
        h.add_probe(4, t + i + 0.1, 20.0)
        rows += h.finalize_due(now=t + i + 3.0)
    back = [r for r in rows if r["ts"] > t + 65]
    assert all(r["probes"] == 3 for r in back)
    assert not [x for x in h.target_health() if x["unreachable"]]


def test_probe_scheduler_spreads_pings_over_the_interval():
    """Pings must not go out as a burst - bursts get rate-limited along the way."""
    import asyncio

    from backend.collectors.ping import ProbeScheduler, ProbeTarget

    sends: list[tuple[float, int]] = []

    class FakeProber:
        def send(self, tid, addr):
            sends.append((time.monotonic(), tid))

        def on_result(self, *a):
            pass

    async def run():
        sch = ProbeScheduler(FakeProber(), interval=0.4, fast_interval=0.2)
        sch.set_targets([ProbeTarget(i, f"192.0.2.{i}", "internet") for i in range(1, 5)])
        await sch.start()
        await asyncio.sleep(1.5)          # at least three full cycles of 0.4 s
        await sch.stop()

    asyncio.run(run())
    assert len(sends) >= 8, f"zu wenige Probes: {len(sends)}"
    deltas = [b[0] - a[0] for a, b in zip(sends, sends[1:])]
    assert min(deltas) >= 0.04, f"Pings zu dicht hintereinander: {min(deltas) * 1000:.0f} ms"
    # every target equally often
    counts = {}
    for _, tid in sends:
        counts[tid] = counts.get(tid, 0) + 1
    assert max(counts.values()) - min(counts.values()) <= 1, counts


import time  # noqa: E402  (for the scheduler test)
