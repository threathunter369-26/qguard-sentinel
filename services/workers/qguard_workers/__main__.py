"""Worker entry point: `qguard-worker` or `python -m qguard_workers`."""

from __future__ import annotations

import argparse
import asyncio

from qguard.common.config import get_settings
from qguard.common.logging import configure_logging

from qguard_workers import handlers  # noqa: F401 - registers job handlers
from qguard_workers.registry import registered_kinds
from qguard_workers.runner import Worker


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qguard-worker",
        description="QGuard Sentinel background worker.",
    )
    parser.add_argument("--worker-id", help="Identifier used in job leases and logs.")
    parser.add_argument(
        "--concurrency", type=int, help="Jobs to run in parallel (default from config)."
    )
    parser.add_argument(
        "--kinds",
        nargs="*",
        help=(
            "Only process these job kinds. Lets a deployment dedicate workers to, say, "
            f"report rendering. Known kinds: {', '.join(registered_kinds())}"
        ),
    )
    parser.add_argument("--poll-interval", type=float, help="Seconds between empty polls.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    configure_logging()
    get_settings()  # fail fast on a misconfigured environment
    worker = Worker(
        worker_id=args.worker_id,
        concurrency=args.concurrency,
        kinds=args.kinds,
        poll_interval=args.poll_interval,
    )
    asyncio.run(worker.run())


if __name__ == "__main__":
    main()
