"""Dependency manifest and lockfile parsers.

Lockfiles are preferred over manifests wherever both exist, because a manifest
states a *range* while a lockfile states what is actually installed. Reporting
a vulnerability against a range produces findings that may not apply to the
build that ships.

Each parser is tolerant: a malformed file yields a warning rather than aborting
the scan, and the warning is surfaced so the resulting coverage gap is visible
instead of silently shrinking the dependency count.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(slots=True)
class Dependency:
    """One resolved software component."""

    ecosystem: str
    name: str
    version: str
    manifest_path: str
    is_direct: bool = True
    scope: str = "runtime"
    """``runtime``, ``development``, ``optional``, ``peer`` or ``build``."""
    depth: int = 0
    parent: str | None = None
    license: str | None = None
    #: True when the version came from a lockfile rather than a range.
    is_pinned: bool = True

    @property
    def purl(self) -> str:
        """Package URL, the canonical cross-ecosystem coordinate."""
        kind = {
            "npm": "npm",
            "PyPI": "pypi",
            "Maven": "maven",
            "Go": "golang",
            "crates.io": "cargo",
            "NuGet": "nuget",
            "Packagist": "composer",
            "RubyGems": "gem",
            "Hex": "hex",
            "Pub": "pub",
        }.get(self.ecosystem, self.ecosystem.lower())
        return f"pkg:{kind}/{self.name}@{self.version}"

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


@dataclass(slots=True)
class ParseOutcome:
    dependencies: list[Dependency] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    lockfiles_seen: list[str] = field(default_factory=list)
    manifests_seen: list[str] = field(default_factory=list)

    def merge(self, other: ParseOutcome) -> None:
        self.dependencies.extend(other.dependencies)
        self.warnings.extend(other.warnings)
        self.lockfiles_seen.extend(other.lockfiles_seen)
        self.manifests_seen.extend(other.manifests_seen)


#: Filenames that identify an ecosystem, and whether the file pins versions.
MANIFEST_FILES: dict[str, tuple[str, bool]] = {
    "package-lock.json": ("npm", True),
    "npm-shrinkwrap.json": ("npm", True),
    "yarn.lock": ("npm", True),
    "pnpm-lock.yaml": ("npm", True),
    "package.json": ("npm", False),
    "poetry.lock": ("PyPI", True),
    "uv.lock": ("PyPI", True),
    "Pipfile.lock": ("PyPI", True),
    "requirements.txt": ("PyPI", False),
    "requirements-dev.txt": ("PyPI", False),
    "pyproject.toml": ("PyPI", False),
    "go.sum": ("Go", True),
    "go.mod": ("Go", False),
    "Cargo.lock": ("crates.io", True),
    "Cargo.toml": ("crates.io", False),
    "composer.lock": ("Packagist", True),
    "composer.json": ("Packagist", False),
    "Gemfile.lock": ("RubyGems", True),
    "Gemfile": ("RubyGems", False),
    "packages.lock.json": ("NuGet", True),
    "pom.xml": ("Maven", False),
    "build.gradle": ("Maven", False),
    "build.gradle.kts": ("Maven", False),
    "gradle.lockfile": ("Maven", True),
}

_VERSION_SPEC = re.compile(r"^([A-Za-z0-9._\-\[\]]+)\s*(?:[=<>!~^]+\s*([0-9][^\s;,#]*))?")
_GO_MOD_REQUIRE = re.compile(r"^\s*([^\s]+)\s+v([^\s/]+)")
_GO_SUM = re.compile(r"^([^\s]+)\s+v([^\s/]+)(?:/go\.mod)?\s+")
_YARN_ENTRY = re.compile(r'^"?((?:@[^@/]+/)?[^@"\s]+)@[^:]*"?:$')
_GEMFILE_LOCK = re.compile(r"^\s{4}([a-zA-Z0-9_\-.]+)\s+\(([^)]+)\)")


def parse_file(path: Path, relative: str) -> ParseOutcome:
    """Parse one manifest or lockfile."""
    outcome = ParseOutcome()
    entry = MANIFEST_FILES.get(path.name)
    if entry is None:
        return outcome
    ecosystem, pinned = entry
    (outcome.lockfiles_seen if pinned else outcome.manifests_seen).append(relative)

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        outcome.warnings.append(f"{relative}: could not be read ({exc.strerror or exc})")
        return outcome

    handlers = {
        "package-lock.json": _parse_npm_lock,
        "npm-shrinkwrap.json": _parse_npm_lock,
        "package.json": _parse_package_json,
        "yarn.lock": _parse_yarn_lock,
        "pnpm-lock.yaml": _parse_pnpm_lock,
        "poetry.lock": _parse_poetry_lock,
        "uv.lock": _parse_uv_lock,
        "Pipfile.lock": _parse_pipfile_lock,
        "requirements.txt": _parse_requirements,
        "requirements-dev.txt": _parse_requirements,
        "pyproject.toml": _parse_pyproject,
        "go.mod": _parse_go_mod,
        "go.sum": _parse_go_sum,
        "Cargo.lock": _parse_cargo_lock,
        "Cargo.toml": _parse_cargo_toml,
        "composer.lock": _parse_composer_lock,
        "composer.json": _parse_composer_json,
        "Gemfile.lock": _parse_gemfile_lock,
        "pom.xml": _parse_pom,
        "packages.lock.json": _parse_nuget_lock,
    }
    handler = handlers.get(path.name)
    if handler is None:
        outcome.warnings.append(
            f"{relative}: recognised as {ecosystem} but no parser is implemented, so its "
            "dependencies are not included in this assessment"
        )
        return outcome

    try:
        handler(raw, relative, outcome)
    except Exception as exc:
        outcome.warnings.append(
            f"{relative}: could not be parsed ({type(exc).__name__}: {exc}), so its "
            "dependencies are missing from this assessment"
        )
    return outcome


# ------------------------------------------------------------------------ npm
def _parse_npm_lock(raw: str, relative: str, outcome: ParseOutcome) -> None:
    data = json.loads(raw)
    version = data.get("lockfileVersion", 1)
    if version >= 2 and "packages" in data:
        for location, info in data["packages"].items():
            if not location or not isinstance(info, dict):
                continue
            name = info.get("name") or location.split("node_modules/")[-1]
            if not name or not info.get("version"):
                continue
            outcome.dependencies.append(
                Dependency(
                    ecosystem="npm",
                    name=name,
                    version=str(info["version"]),
                    manifest_path=relative,
                    is_direct=location.count("node_modules") <= 1,
                    scope="development" if info.get("dev") else "runtime",
                    depth=max(0, location.count("node_modules") - 1),
                    license=info.get("license"),
                )
            )
    else:

        def walk(deps: dict[str, Any], depth: int, parent: str | None) -> None:
            for name, info in deps.items():
                if not isinstance(info, dict) or "version" not in info:
                    continue
                outcome.dependencies.append(
                    Dependency(
                        ecosystem="npm",
                        name=name,
                        version=str(info["version"]),
                        manifest_path=relative,
                        is_direct=depth == 0,
                        scope="development" if info.get("dev") else "runtime",
                        depth=depth,
                        parent=parent,
                    )
                )
                if isinstance(info.get("dependencies"), dict):
                    walk(info["dependencies"], depth + 1, name)

        walk(data.get("dependencies", {}), 0, None)


def _parse_package_json(raw: str, relative: str, outcome: ParseOutcome) -> None:
    data = json.loads(raw)
    for field_name, scope in (
        ("dependencies", "runtime"),
        ("devDependencies", "development"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
    ):
        for name, spec in (data.get(field_name) or {}).items():
            cleaned = str(spec).lstrip("^~>=< v")
            if not cleaned or not cleaned[0].isdigit():
                # A range, a git URL or a workspace link: not a resolved version.
                continue
            outcome.dependencies.append(
                Dependency(
                    ecosystem="npm",
                    name=name,
                    version=cleaned,
                    manifest_path=relative,
                    scope=scope,
                    is_pinned=False,
                )
            )


def _parse_yarn_lock(raw: str, relative: str, outcome: ParseOutcome) -> None:
    current: str | None = None
    for line in raw.splitlines():
        if not line.startswith(("#", " ", "\t")) and line.strip().endswith(":"):
            match = _YARN_ENTRY.match(line.strip())
            current = match.group(1) if match else None
        elif current and line.strip().startswith(("version ", 'version "')):
            version = line.split(None, 1)[1].strip().strip('"')
            outcome.dependencies.append(
                Dependency(ecosystem="npm", name=current, version=version, manifest_path=relative)
            )
            current = None


def _parse_pnpm_lock(raw: str, relative: str, outcome: ParseOutcome) -> None:
    data = yaml.safe_load(raw) or {}
    packages = data.get("packages") or {}
    for location, info in packages.items():
        text = str(location).lstrip("/")
        if "@" not in text:
            continue
        name, _, version = text.rpartition("@")
        name = name.rstrip("/")
        if not name or not version:
            continue
        outcome.dependencies.append(
            Dependency(
                ecosystem="npm",
                name=name,
                version=version.split("(")[0],
                manifest_path=relative,
                scope="development" if (info or {}).get("dev") else "runtime",
            )
        )


# ----------------------------------------------------------------------- PyPI
def _parse_poetry_lock(raw: str, relative: str, outcome: ParseOutcome) -> None:
    data = tomllib.loads(raw)
    for package in data.get("package", []):
        if package.get("name") and package.get("version"):
            outcome.dependencies.append(
                Dependency(
                    ecosystem="PyPI",
                    name=package["name"],
                    version=str(package["version"]),
                    manifest_path=relative,
                    scope="development" if package.get("category") == "dev" else "runtime",
                )
            )


def _parse_uv_lock(raw: str, relative: str, outcome: ParseOutcome) -> None:
    data = tomllib.loads(raw)
    for package in data.get("package", []):
        if package.get("name") and package.get("version"):
            outcome.dependencies.append(
                Dependency(
                    ecosystem="PyPI",
                    name=package["name"],
                    version=str(package["version"]),
                    manifest_path=relative,
                )
            )


def _parse_pipfile_lock(raw: str, relative: str, outcome: ParseOutcome) -> None:
    data = json.loads(raw)
    for section, scope in (("default", "runtime"), ("develop", "development")):
        for name, info in (data.get(section) or {}).items():
            version = str(info.get("version", "")).lstrip("=")
            if version:
                outcome.dependencies.append(
                    Dependency(
                        ecosystem="PyPI",
                        name=name,
                        version=version,
                        manifest_path=relative,
                        scope=scope,
                    )
                )


def _parse_requirements(raw: str, relative: str, outcome: ParseOutcome) -> None:
    scope = "development" if "dev" in relative.lower() else "runtime"
    for line in raw.splitlines():
        text = line.split("#", 1)[0].strip()
        if not text or text.startswith("-"):
            continue
        if "==" not in text:
            # A range or an unpinned requirement: the installed version is
            # unknown, so reporting a vulnerability against it would be a guess.
            continue
        name, _, version = text.partition("==")
        name = name.split("[")[0].strip()
        version = version.split(";")[0].strip()
        if name and version:
            outcome.dependencies.append(
                Dependency(
                    ecosystem="PyPI",
                    name=name,
                    version=version,
                    manifest_path=relative,
                    scope=scope,
                )
            )


def _parse_pyproject(raw: str, relative: str, outcome: ParseOutcome) -> None:
    data = tomllib.loads(raw)
    specs: list[tuple[str, str]] = []
    for spec in (data.get("project") or {}).get("dependencies") or []:
        specs.append((str(spec), "runtime"))
    for group, items in (data.get("dependency-groups") or {}).items():
        for spec in items or []:
            if isinstance(spec, str):
                specs.append((spec, "development" if "dev" in group else "runtime"))
    poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        version = spec if isinstance(spec, str) else (spec or {}).get("version", "")
        specs.append((f"{name}{version}", "runtime"))

    for spec, scope in specs:
        match = _VERSION_SPEC.match(spec.strip())
        if not match or not match.group(2):
            continue
        outcome.dependencies.append(
            Dependency(
                ecosystem="PyPI",
                name=match.group(1).split("[")[0],
                version=match.group(2),
                manifest_path=relative,
                scope=scope,
                is_pinned=False,
            )
        )


# ------------------------------------------------------------------------- Go
def _parse_go_mod(raw: str, relative: str, outcome: ParseOutcome) -> None:
    in_require = False
    for line in raw.splitlines():
        text = line.strip()
        if text.startswith("require ("):
            in_require = True
            continue
        if in_require and text == ")":
            in_require = False
            continue
        candidate = text.removeprefix("require ").strip()
        if not candidate or candidate.startswith("//"):
            continue
        if in_require or text.startswith("require "):
            match = _GO_MOD_REQUIRE.match(candidate)
            if match:
                outcome.dependencies.append(
                    Dependency(
                        ecosystem="Go",
                        name=match.group(1),
                        version=f"v{match.group(2)}",
                        manifest_path=relative,
                        scope="development" if "// indirect" in line else "runtime",
                        is_direct="// indirect" not in line,
                        is_pinned=False,
                    )
                )


def _parse_go_sum(raw: str, relative: str, outcome: ParseOutcome) -> None:
    seen: set[tuple[str, str]] = set()
    for line in raw.splitlines():
        match = _GO_SUM.match(line.strip())
        if not match:
            continue
        key = (match.group(1), match.group(2))
        if key in seen:
            continue
        seen.add(key)
        outcome.dependencies.append(
            Dependency(
                ecosystem="Go",
                name=match.group(1),
                version=f"v{match.group(2)}",
                manifest_path=relative,
            )
        )


# ------------------------------------------------------------------- Rust
def _parse_cargo_lock(raw: str, relative: str, outcome: ParseOutcome) -> None:
    data = tomllib.loads(raw)
    for package in data.get("package", []):
        if package.get("name") and package.get("version"):
            outcome.dependencies.append(
                Dependency(
                    ecosystem="crates.io",
                    name=package["name"],
                    version=str(package["version"]),
                    manifest_path=relative,
                )
            )


def _parse_cargo_toml(raw: str, relative: str, outcome: ParseOutcome) -> None:
    data = tomllib.loads(raw)
    for section, scope in (
        ("dependencies", "runtime"),
        ("dev-dependencies", "development"),
        ("build-dependencies", "build"),
    ):
        for name, spec in (data.get(section) or {}).items():
            version = spec if isinstance(spec, str) else (spec or {}).get("version", "")
            cleaned = str(version).lstrip("^~>=< ")
            if cleaned and cleaned[0].isdigit():
                outcome.dependencies.append(
                    Dependency(
                        ecosystem="crates.io",
                        name=name,
                        version=cleaned,
                        manifest_path=relative,
                        scope=scope,
                        is_pinned=False,
                    )
                )


# --------------------------------------------------------------------- PHP
def _parse_composer_lock(raw: str, relative: str, outcome: ParseOutcome) -> None:
    data = json.loads(raw)
    for section, scope in (("packages", "runtime"), ("packages-dev", "development")):
        for package in data.get(section) or []:
            if package.get("name") and package.get("version"):
                outcome.dependencies.append(
                    Dependency(
                        ecosystem="Packagist",
                        name=package["name"],
                        version=str(package["version"]).lstrip("v"),
                        manifest_path=relative,
                        scope=scope,
                        license=", ".join(package.get("license") or []) or None,
                    )
                )


def _parse_composer_json(raw: str, relative: str, outcome: ParseOutcome) -> None:
    data = json.loads(raw)
    for section, scope in (("require", "runtime"), ("require-dev", "development")):
        for name, spec in (data.get(section) or {}).items():
            if "/" not in name:
                continue
            cleaned = str(spec).lstrip("^~>=< v")
            if cleaned and cleaned[0].isdigit():
                outcome.dependencies.append(
                    Dependency(
                        ecosystem="Packagist",
                        name=name,
                        version=cleaned,
                        manifest_path=relative,
                        scope=scope,
                        is_pinned=False,
                    )
                )


# -------------------------------------------------------------------- Ruby
def _parse_gemfile_lock(raw: str, relative: str, outcome: ParseOutcome) -> None:
    for line in raw.splitlines():
        match = _GEMFILE_LOCK.match(line)
        if match:
            outcome.dependencies.append(
                Dependency(
                    ecosystem="RubyGems",
                    name=match.group(1),
                    version=match.group(2).split(",")[0].strip(),
                    manifest_path=relative,
                )
            )


# -------------------------------------------------------------------- Java
def _parse_pom(raw: str, relative: str, outcome: ParseOutcome) -> None:
    from defusedxml import ElementTree

    # defusedxml: a pom.xml from a scanned repository is untrusted input, and
    # the stdlib parser resolves external entities.
    root = ElementTree.fromstring(raw)
    namespace = ""
    if root.tag.startswith("{"):
        namespace = root.tag[: root.tag.index("}") + 1]

    properties: dict[str, str] = {}
    for prop in root.findall(f"{namespace}properties/*"):
        tag = prop.tag.replace(namespace, "")
        if prop.text:
            properties[tag] = prop.text.strip()

    for dependency in root.iter(f"{namespace}dependency"):
        group = dependency.findtext(f"{namespace}groupId", "").strip()
        artifact = dependency.findtext(f"{namespace}artifactId", "").strip()
        version = dependency.findtext(f"{namespace}version", "").strip()
        scope = dependency.findtext(f"{namespace}scope", "compile").strip()
        if version.startswith("${") and version.endswith("}"):
            version = properties.get(version[2:-1], "")
        if group and artifact and version:
            outcome.dependencies.append(
                Dependency(
                    ecosystem="Maven",
                    name=f"{group}:{artifact}",
                    version=version,
                    manifest_path=relative,
                    scope="development" if scope in ("test", "provided") else "runtime",
                    is_pinned=False,
                )
            )


def _parse_nuget_lock(raw: str, relative: str, outcome: ParseOutcome) -> None:
    data = json.loads(raw)
    for framework in (data.get("dependencies") or {}).values():
        for name, info in (framework or {}).items():
            version = str((info or {}).get("resolved", "")).strip()
            if version:
                outcome.dependencies.append(
                    Dependency(
                        ecosystem="NuGet",
                        name=name,
                        version=version,
                        manifest_path=relative,
                    )
                )
