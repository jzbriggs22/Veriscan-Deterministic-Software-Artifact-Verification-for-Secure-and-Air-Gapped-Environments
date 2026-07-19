#!/usr/bin/env python3
"""
Production server entrypoint for the AI Agent Governance MVP.

Usage:
    python serve.py                                   # defaults
    python serve.py --config config/governance.yaml   # custom config
    python serve.py --db /data/governance.db          # persistent DB
    python serve.py --host 0.0.0.0 --port 8000        # bind address
    python serve.py --detection-interval 60           # 1-minute cycles
    python serve.py --no-scheduler                    # API only, no background detection
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("governance.serve")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="AI Agent Governance MVP — production server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--config", default="config/governance.yaml",
                   help="Path to governance YAML config file")
    p.add_argument("--db", default="governance.db",
                   help="Path to SQLite database file (use :memory: for in-memory)")
    p.add_argument("--host", default="0.0.0.0", help="Bind host")
    p.add_argument("--port", type=int, default=8000, help="Bind port")
    p.add_argument("--detection-interval", type=float, default=300.0,
                   help="Seconds between background detection cycles")
    p.add_argument("--no-scheduler", action="store_true",
                   help="Disable background detection scheduler (API-only mode)")
    p.add_argument("--webhook-url", action="append", dest="webhook_urls", default=[],
                   metavar="URL", help="Webhook URL to notify (repeatable)")
    p.add_argument("--webhook-format", choices=["slack", "generic"], default="generic",
                   help="Webhook payload format")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)

    # ── Imports (after log level is set) ──────────────────────────────────────
    try:
        import uvicorn
    except ImportError:
        logger.error("uvicorn not installed — run: pip install uvicorn[standard]")
        sys.exit(1)

    from src.api.app import app, configure
    from src.detection.detector import DriftDetector
    from src.engine.alerts import AlertEngine
    from src.engine.rollback import RollbackEngine
    from src.engine.events import get_broker
    from src.engine.scheduler import DetectionScheduler
    from src.engine.webhooks import WebhookConfig, WebhookDispatcher
    from src.governance.config import GovernanceConfig
    from src.ingestion.store import DecisionStore

    # ── Load config ────────────────────────────────────────────────────────────
    try:
        config = GovernanceConfig.from_yaml(args.config)
        logger.info("Loaded governance config from %s", args.config)
    except FileNotFoundError:
        logger.warning("Config file %r not found — using built-in defaults", args.config)
        config = GovernanceConfig.default()

    # ── Open store ─────────────────────────────────────────────────────────────
    store = DecisionStore(args.db)
    logger.info("Opened database: %s", args.db)

    # ── Wire engines ───────────────────────────────────────────────────────────
    detector = DriftDetector(store, config)
    alert_engine = AlertEngine(store, config)
    rollback_engine = RollbackEngine(store, config)

    # ── Webhook dispatcher ─────────────────────────────────────────────────────
    dispatcher: WebhookDispatcher | None = None
    if args.webhook_urls:
        wh_configs = [
            WebhookConfig(url=url, format=args.webhook_format)
            for url in args.webhook_urls
        ]
        dispatcher = WebhookDispatcher(wh_configs)
        logger.info("Webhooks configured: %s", args.webhook_urls)

    # ── Background scheduler ───────────────────────────────────────────────────
    scheduler: DetectionScheduler | None = None
    if not args.no_scheduler:
        scheduler = DetectionScheduler(
            store=store,
            detector=detector,
            alert_engine=alert_engine,
            rollback_engine=rollback_engine,
            dispatcher=dispatcher,
            # Same singleton the /governance/events/stream endpoint reads from;
            # without it the SSE stream carries only keep-alive heartbeats.
            event_broker=get_broker(),
        )
        scheduler.start(interval_seconds=args.detection_interval)
        logger.info(
            "Background scheduler started (interval=%.0fs)", args.detection_interval
        )

    configure(config, store, scheduler=scheduler)

    # ── Graceful shutdown ──────────────────────────────────────────────────────
    def _shutdown(sig, frame):
        logger.info("Shutting down (signal %d)…", sig)
        if scheduler:
            scheduler.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ── Serve ──────────────────────────────────────────────────────────────────
    logger.info("Starting server on %s:%d", args.host, args.port)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=args.log_level.lower(),
    )


if __name__ == "__main__":
    main()
