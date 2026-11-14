"""Dedicated scheduler and control-plane runner for VPN Panel."""
from __future__ import annotations

import logging
import signal
import threading

from app.config import get_settings
from app.services.scheduler import start_scheduler
from app.services.security_hardening import validate_runtime_security

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vpn-panel.background")
_STOP = threading.Event()


def _request_stop(signum, _frame) -> None:
    logger.info("Background runner received signal %s", signum)
    _STOP.set()


def main() -> int:
    validate_runtime_security(get_settings())
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    scheduler = start_scheduler()
    logger.info("VPN Panel dedicated background scheduler started")
    _STOP.wait()

    try:
        scheduler.shutdown(wait=False)
    except Exception:
        logger.exception("Scheduler shutdown failed")
    logger.info("VPN Panel dedicated background runner stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
