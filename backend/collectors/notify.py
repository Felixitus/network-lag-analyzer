"""Sending notifications: ntfy, Telegram, e-mail. Each channel on its own - one that fails
does not keep the others from delivering. Blocking (HTTP, SMTP): call from a thread."""
from __future__ import annotations

import smtplib
import ssl
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


def send_mail(cfg, title: str, body: str, priority: str, timeout: float = 15) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"[Network Lag Analyzer] {title}"
    msg["From"] = cfg.mail_from or cfg.smtp_username or "network-lag-analyzer@localhost"
    msg["To"] = cfg.mail_to
    msg.set_content(body)
    with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=timeout) as s:
        if cfg.smtp_starttls:
            s.starttls(context=ssl.create_default_context())
        if cfg.smtp_username:
            s.login(cfg.smtp_username, cfg.smtp_password)
        s.send_message(msg)


SENDERS = {"ntfy": send_ntfy, "telegram": send_telegram, "email": send_mail}


def deliver(cfg, title: str, body: str, priority: str = "default", senders: dict | None = None) -> dict[str, str | None]:
    """→ {channel: None (sent) or error text}."""
    out: dict[str, str | None] = {}
    for ch in channels(cfg):
        try:
            (senders or SENDERS)[ch](cfg, title, body, priority)
            out[ch] = None
        except Exception as e:  # noqa: BLE001 - every channel reports its own failure
            out[ch] = f"{type(e).__name__}: {str(e)[:160]}"
    return out
