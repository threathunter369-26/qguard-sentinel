"""Security assessment engines.

Importing this package registers every engine with the SDK registry, which is
how the orchestrator discovers what a deployment can run.
"""

from qguard_scanner.engines import secrets

__all__ = ["secrets"]
