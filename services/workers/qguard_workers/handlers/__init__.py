"""Job handlers.

Importing this package registers every handler, which is what the worker's
registry lookup depends on.
"""

from qguard_workers.handlers import maintenance, scan

__all__ = ["maintenance", "scan"]
