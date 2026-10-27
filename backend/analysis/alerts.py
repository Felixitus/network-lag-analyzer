"""When to notify: alert states with a minimum duration, a cooldown and an "all clear".

A condition is checked every round. It becomes an alert only after it held for its
minimum duration (one lost burst is no message), is repeated at most once per cooldown
while it lasts, and ends with one "resolved" message that says how long it lasted.
One-shot events (a new device, a DSL resync) are sent once each.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Message:
    key: str
    title: str
    body: str
    priority: str = "default"         # low | default | high
    kind: str = "alert"               # alert | repeat | resolved | event | test


@dataclass
class _State:
    since: float | None = None        # condition true since
    active: bool = False              # message sent, alert is on
    last_sent: float = 0.0
    text: str = ""


@dataclass
class Alerts:
    cooldown_s: float = 1800
    states: dict[str, _State] = field(default_factory=dict)

    def condition(self, key: str, now: float, true: bool, title: str, text: str, min_s: float = 0,
                  priority: str = "high") -> list[Message]:
        st = self.states.setdefault(key, _State())
        out: list[Message] = []
        if true:
            st.since = st.since if st.since is not None else now
            st.text = text
            if not st.active and now - st.since >= min_s:
                st.active, st.last_sent = True, now
                out.append(Message(key, title, text, priority, "alert"))
            elif st.active and now - st.last_sent >= self.cooldown_s:
                st.last_sent = now
                out.append(Message(key, f"Still: {title}", text, priority, "repeat"))
        else:
            if st.active:
                lasted = now - (st.since if st.since is not None else now)
                out.append(Message(key, f"Resolved: {title}", f"Lasted {_dur(lasted)}. {st.text}".strip(), "low", "resolved"))
            st.since, st.active = None, False
        return out

    def active(self) -> list[str]:
        return [k for k, s in self.states.items() if s.active]


def _dur(s: float) -> str:
    s = int(s)
    if s < 120:
        return f"{s} s"
    if s < 7200:
        return f"{s // 60} min"
    return f"{s // 3600} h {(s % 3600) // 60} min"
