"""Einstiegspunkt: `python -m backend.main [--config PATH]`."""
from __future__ import annotations

import argparse
import logging
import os
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Network Lag Analyzer")
    parser.add_argument("--config", default=os.environ.get("NLA_CONFIG"), help="Pfad zur config.yaml")
    parser.add_argument("--dev", action="store_true", help="Dev-Modus mit simulierten Daten (DEMO)")
    parser.add_argument("--data-dir", help="Datenverzeichnis überschreiben")
    parser.add_argument("--port", type=int, help="Port überschreiben")
    args = parser.parse_args()
    os.umask(0o027)   # Datenbank/PCAPs nicht weltlesbar (enthält ggf. FRITZ!Box-Zugangsdaten)
    if args.dev:
        os.environ["NLA_DEV_MODE"] = "1"
    if args.data_dir:
        os.environ["NLA_DATA_DIR"] = args.data_dir
    if args.port:
        os.environ["NLA_PORT"] = str(args.port)

    # journald ergänzt Zeitstempel selbst
    logging.basicConfig(level=os.environ.get("NLA_LOG_LEVEL", "INFO"),
                        format="%(levelname)s %(name)s: %(message)s", stream=sys.stdout)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    import uvicorn

    from .api import create_app
    from .core import Core

    core = Core(args.config)
    app = create_app(core)
    uvicorn.run(app, host=core.cfg.server.host, port=core.cfg.server.port, log_level="warning",
                access_log=False, proxy_headers=False, timeout_graceful_shutdown=5)


if __name__ == "__main__":
    main()
