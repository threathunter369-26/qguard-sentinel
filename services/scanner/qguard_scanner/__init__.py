"""QGuard Sentinel scanner SDK and security assessment engines.

Engines are independently replaceable: each implements the
:class:`~qguard_scanner.sdk.engine.SecurityEngine` contract, emits
:class:`~qguard_scanner.sdk.finding.ScanFinding` objects, and knows nothing
about the database, the API or any other engine.
"""

__version__ = "1.0.0"
