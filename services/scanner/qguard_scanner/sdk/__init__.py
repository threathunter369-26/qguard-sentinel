"""The contract between the platform and its security engines."""

from qguard_scanner.sdk.engine import (
    EngineCapability,
    EngineContext,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    SecurityEngine,
)
from qguard_scanner.sdk.finding import (
    CodeLocation,
    Evidence,
    NetworkLocation,
    ScanFinding,
    ScanTarget,
)
from qguard_scanner.sdk.registry import EngineRegistry, get_registry, register_engine

__all__ = [
    "CodeLocation",
    "EngineCapability",
    "EngineContext",
    "EngineMetadata",
    "EngineRegistry",
    "EngineResult",
    "EngineStatus",
    "Evidence",
    "NetworkLocation",
    "ScanFinding",
    "ScanTarget",
    "SecurityEngine",
    "get_registry",
    "register_engine",
]
