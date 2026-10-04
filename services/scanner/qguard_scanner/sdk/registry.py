"""Engine registry.

Engines register themselves so the orchestrator can discover what is available
without importing each one by name, and so a deployment can add an engine by
installing a package rather than editing the platform.
"""

from __future__ import annotations

from collections.abc import Iterator

from qguard_scanner.sdk.engine import EngineMetadata, SecurityEngine


class EngineRegistry:
    """Maps engine keys to engine classes."""

    def __init__(self) -> None:
        self._engines: dict[str, type[SecurityEngine]] = {}

    def register(self, engine_cls: type[SecurityEngine]) -> type[SecurityEngine]:
        key = engine_cls.metadata.key
        existing = self._engines.get(key)
        if existing is not None and existing is not engine_cls:
            raise ValueError(
                f"Engine key {key!r} is already registered to {existing.__name__}. "
                "Engine keys must be unique because findings are attributed by key."
            )
        self._engines[key] = engine_cls
        return engine_cls

    def get(self, key: str) -> type[SecurityEngine] | None:
        return self._engines.get(key)

    def create(self, key: str) -> SecurityEngine | None:
        engine_cls = self._engines.get(key)
        return engine_cls() if engine_cls is not None else None

    def keys(self) -> list[str]:
        return sorted(self._engines)

    def metadata(self) -> list[EngineMetadata]:
        return [cls.metadata for cls in self._engines.values()]

    def for_target_kind(self, kind: str) -> list[str]:
        return sorted(
            key for key, cls in self._engines.items() if kind in cls.metadata.target_kinds
        )

    def passive_keys(self) -> list[str]:
        return sorted(k for k, c in self._engines.items() if c.metadata.is_passive)

    def __iter__(self) -> Iterator[type[SecurityEngine]]:
        return iter(self._engines.values())

    def __len__(self) -> int:
        return len(self._engines)

    def __contains__(self, key: object) -> bool:
        return key in self._engines


_registry = EngineRegistry()


def get_registry() -> EngineRegistry:
    return _registry


def register_engine(engine_cls: type[SecurityEngine]) -> type[SecurityEngine]:
    """Class decorator registering an engine."""
    return _registry.register(engine_cls)
