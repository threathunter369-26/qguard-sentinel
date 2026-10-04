"""QGuard Sentinel background workers.

Workers poll the PostgreSQL job queue, run one job at a time per slot, and
report progress so the UI reflects real state rather than a guess.
"""

__version__ = "1.0.0"
