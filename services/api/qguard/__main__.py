"""Entry point: `python -m qguard` or the `qguard-api` console script."""

from __future__ import annotations

import uvicorn

from qguard.common.config import get_settings
from qguard.common.logging import configure_logging


def main() -> None:
    settings = get_settings()
    configure_logging()
    uvicorn.run(
        "qguard.asgi:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.env == "development",
        log_config=None,  # structlog owns logging
        access_log=False,  # RequestContextMiddleware logs requests instead
        forwarded_allow_ips="*" if settings.trusted_hosts else None,
        timeout_keep_alive=30,
    )


if __name__ == "__main__":
    main()
