"""Sending notifications: ntfy, Telegram, e-mail. Each channel on its own - one that fails
does not keep the others from delivering. Blocking (HTTP, SMTP): call from a thread."""
from __future__ import annotations

import html
import re
import smtplib
import ssl
import time
from email.message import EmailMessage

import httpx

PRIORITY_NTFY = {"low": "2", "default": "3", "high": "4"}


def channels(cfg) -> list[str]:
    out = []
    if cfg.ntfy_url:
        out.append("ntfy")
    if cfg.telegram_bot_token and cfg.telegram_chat_id:
        out.append("telegram")
    if cfg.smtp_host and cfg.mail_to:
        out.append("email")
    return out


def send_ntfy(cfg, title: str, body: str, priority: str, timeout: float = 10) -> None:
    headers = {"Title": title.encode("utf-8").decode("latin-1", "replace"), "Priority": PRIORITY_NTFY.get(priority, "3"),
               "Tags": "satellite_antenna"}
    if cfg.ntfy_token:
        headers["Authorization"] = f"Bearer {cfg.ntfy_token}"
    r = httpx.post(cfg.ntfy_url, content=body.encode("utf-8"), headers=headers, timeout=timeout)
    r.raise_for_status()


def send_telegram(cfg, title: str, body: str, priority: str, timeout: float = 10) -> None:
    try:
        r = httpx.post(f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendMessage",
                       json={"chat_id": cfg.telegram_chat_id, "text": f"{title}\n{body}",
                             "disable_notification": priority == "low"}, timeout=timeout)
    except httpx.HTTPError as e:
        raise RuntimeError(f"Telegram not reachable ({type(e).__name__})") from None   # the URL holds the token
    if r.status_code != 200:
        # never put the bot token into an error message: it would end up in logs and the UI
        raise RuntimeError(f"Telegram answered HTTP {r.status_code}")


# kind → (accent colour, label, subject mark)
KIND_STYLE = {
    "alert": ("#d14343", "Alert", "⚠ "), "repeat": ("#d14343", "Still on", "⚠ "),
    "resolved": ("#2e9e5b", "Resolved", "✓ "), "event": ("#c88a12", "Event", ""),
    "report": ("#3a6fd8", "Weekly report", ""), "test": ("#6b7280", "Test", ""),
}
# "INTERNET OUTAGES: 3, ..." and "DNS PAST PI-HOLE (signs, not proof):" start a section
_HEADING = re.compile(r"^([A-Z][A-Z0-9 !/\-]+(?: \([^)]*\))?):\s*(.*)$")


def _blocks(body: str) -> list[tuple[str, str, str]]:
    """Plain text → ("h", heading, rest) | ("li", text, "") | ("p", text, "")."""
    out = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _HEADING.match(line)
        if m and len(m.group(1)) >= 3:
            head, rest = m.group(1), m.group(2)
            if rest and len(rest) <= 4:              # "NEW DEVICES: 2" reads better as one line
                head, rest = f"{head} · {rest}", ""
            out.append(("h", head, rest))
        elif line.startswith("- "):
            out.append(("li", line[2:], ""))
        else:
            out.append(("p", line, ""))
    return out


def mail_html(title: str, body: str, kind: str = "alert", link: str | None = None, when: float | None = None) -> str:
    """A compact HTML version of a message. Inline styles only: mail clients drop <style> blocks."""
    color, label, _ = KIND_STYLE.get(kind, KIND_STYLE["event"])
    e = html.escape
    parts, in_list = [], False
    for typ, a, b in _blocks(body):
        if typ != "li" and in_list:
            parts.append("</ul>")
            in_list = False
        if typ == "h":
            parts.append(f'<div style="margin:14px 0 4px;font-size:11px;letter-spacing:.06em;color:#6b7280;font-weight:600">'
                         f'{e(a)}</div>' + (f'<div style="margin:0 0 4px">{e(b)}</div>' if b else ""))
        elif typ == "li":
            if not in_list:
                parts.append('<ul style="margin:2px 0 6px;padding-left:18px">')
                in_list = True
            parts.append(f'<li style="margin:2px 0">{e(a)}</li>')
        else:
            parts.append(f'<div style="margin:0 0 6px">{e(a)}</div>')
    if in_list:
        parts.append("</ul>")
    stamp = time.strftime("%d.%m.%Y %H:%M", time.localtime(when or time.time()))
    button = (f'<a href="{e(link, quote=True)}" style="display:inline-block;margin-top:12px;padding:7px 14px;border-radius:6px;'
              f'background:{color};color:#fff;text-decoration:none;font-size:13px">Open the analyzer</a>') if link else ""
    return (
        '<!doctype html><html><body style="margin:0;padding:16px;background:#f3f4f6">'
        '<div style="max-width:560px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;'
        f'border-top:4px solid {color};font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;'
        'font-size:14px;line-height:1.45;color:#111827">'
        '<div style="padding:14px 18px 16px">'
        f'<div style="font-size:11px;letter-spacing:.06em;color:{color};font-weight:700">{e(label.upper())}</div>'
        f'<div style="font-size:17px;font-weight:600;margin:2px 0 10px">{e(title)}</div>'
        f'{"".join(parts)}{button}</div>'
        f'<div style="padding:8px 18px;background:#f9fafb;color:#9ca3af;font-size:11px">Network Lag Analyzer · {stamp}</div>'
        '</div></body></html>')


def send_mail(cfg, title: str, body: str, priority: str, timeout: float = 15, kind: str = "alert",
              link: str | None = None) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"{KIND_STYLE.get(kind, KIND_STYLE['event'])[2]}{title} · Network Lag Analyzer"
    msg["From"] = cfg.mail_from or cfg.smtp_username or "network-lag-analyzer@localhost"
    msg["To"] = cfg.mail_to
    msg.set_content(body + (f"\n\n{link}" if link else ""))
    msg.add_alternative(mail_html(title, body, kind, link), subtype="html")
    ctx = ssl.create_default_context()
    if getattr(cfg, "smtp_tls", False):
        conn = smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=timeout, context=ctx)
    else:
        conn = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=timeout)
    with conn as s:
        if cfg.smtp_starttls and not getattr(cfg, "smtp_tls", False):
            s.starttls(context=ctx)
        if cfg.smtp_username:
            s.login(cfg.smtp_username, cfg.smtp_password)
        s.send_message(msg)


SENDERS = {"ntfy": send_ntfy, "telegram": send_telegram, "email": send_mail}


def deliver(cfg, title: str, body: str, priority: str = "default", senders: dict | None = None,
            kind: str = "alert", link: str | None = None) -> dict[str, str | None]:
    """→ {channel: None (sent) or error text}."""
    out: dict[str, str | None] = {}
    for ch in channels(cfg):
        try:
            extra = {"kind": kind, "link": link} if ch == "email" else {}
            (senders or SENDERS)[ch](cfg, title, body, priority, **extra)
            out[ch] = None
        except Exception as e:  # noqa: BLE001 - every channel reports its own failure
            out[ch] = f"{type(e).__name__}: {str(e)[:160]}"
    return out
