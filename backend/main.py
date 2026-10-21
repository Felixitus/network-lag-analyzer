"""Entry point: `python -m backend.main [--config PATH]`."""
from __future__ import annotations

import argparse
import logging
import os
import sys


def bind_address(configured: str, dev_mode: bool) -> str:
    """Resolve server.host. "auto" = the LAN address only, never every interface by accident.

    Without a LAN address yet (boot, no default route) the service exits with an
    error instead of guessing: "0.0.0.0" would be unsafe, "127.0.0.1" would stay
    unreachable for good. systemd (Restart=on-failure) tries again a few seconds later.
    """
    if configured != "auto":
        return configured
    if dev_mode:
        return "127.0.0.1"
    from .util import netinfo
    route = netinfo.default_route()
    ip = netinfo.primary_ipv4(route.interface) if route else None
    if ip:
        return ip
    logging.getLogger("nla").error("server.host is 'auto', but no LAN address is available yet - exiting, "
                                   "systemd will retry. Set server.host in config.yaml to bind elsewhere.")
    raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Network Lag Analyzer")
    parser.add_argument("--config", default=os.environ.get("NLA_CONFIG"), help="Path to config.yaml")
    parser.add_argument("--dev", action="store_true", help="Dev mode with simulated data (DEMO)")
    parser.add_argument("--data-dir", help="Override the data directory")
    parser.add_argument("--port", type=int, help="Override the port")
    args = parser.parse_args()
    os.umask(0o027)   # database/PCAPs not world-readable (may contain FRITZ!Box credentials)
    if args.dev:
        os.environ["NLA_DEV_MODE"] = "1"
    if args.data_dir:
        os.environ["NLA_DATA_DIR"] = args.data_dir
    if args.port:
        os.environ["NLA_PORT"] = str(args.port)

    # journald adds timestamps itself
    logging.basicConfig(level=os.environ.get("NLA_LOG_LEVEL", "INFO"),
                        format="%(levelname)s %(name)s: %(message)s", stream=sys.stdout)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    import uvicorn

    from .api import create_app
    from .core import Core

    core = Core(args.config)
    app = create_app(core)
    host = bind_address(core.cfg.server.host, core.cfg.dev_mode)
    logging.getLogger("nla").info("Web UI listening on %s:%s", host, core.cfg.server.port)
    uvicorn.run(app, host=host, port=core.cfg.server.port, log_level="warning",
                access_log=False, proxy_headers=False, timeout_graceful_shutdown=5)


if __name__ == "__main__":
    main()
