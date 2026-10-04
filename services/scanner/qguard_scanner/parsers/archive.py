"""Bounded, non-extracting ZIP reader for untrusted archives.

APKs, AABs and IPAs are ZIP files supplied by whoever is being assessed, so
reading one is handling hostile input. Three attacks are specifically defended
against:

* **Zip bombs** — a small archive whose members expand to far more than
  available memory. Member and total uncompressed sizes are checked against
  the central directory *before* decompression, and the decompressed stream is
  read through a hard cap so a lying header cannot win either.
* **Path traversal** — member names like ``../../etc/passwd`` or absolute
  paths. Nothing here writes to disk, which removes the attack entirely; the
  names are still validated so a traversal attempt is *reported*, because an
  archive containing one is itself a finding.
* **Symlink members** — a ZIP can mark a member as a symlink, which turns
  extraction into arbitrary file read. Those members are refused and recorded.

No member is ever extracted to the filesystem and nothing is executed.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Largest single member this reader will decompress.
MAX_MEMBER_BYTES = 48 * 1024 * 1024

#: Largest total uncompressed size across all members read in one session.
MAX_TOTAL_BYTES = 512 * 1024 * 1024

#: Compression ratio above which a member is treated as a zip bomb rather
#: than decompressed. Legitimate text and XML reach roughly 20:1; 200:1 is
#: only produced deliberately.
MAX_COMPRESSION_RATIO = 200

#: Largest number of members considered. An archive with more is read up to
#: the limit and the shortfall is reported.
MAX_MEMBERS = 50_000

#: Unix file mode bit indicating a symbolic link, in the high 16 bits of
#: ``external_attr``.
_S_IFLNK = 0xA000


class ArchiveError(ValueError):
    """The archive could not be read."""


@dataclass(slots=True)
class MemberInfo:
    """One archive member, as described by the central directory."""

    name: str
    compressed_size: int
    uncompressed_size: int
    is_directory: bool
    is_symlink: bool
    crc: int

    @property
    def compression_ratio(self) -> float:
        if self.compressed_size <= 0:
            return 0.0
        return self.uncompressed_size / self.compressed_size

    @property
    def suffix(self) -> str:
        return Path(self.name).suffix.lower()


@dataclass(slots=True)
class ArchiveRefusal:
    """A member that was not read, and why."""

    name: str
    reason: str


@dataclass(slots=True)
class SafeArchive:
    """A bounded view over a ZIP archive.

    Used as a context manager::

        with SafeArchive.open(path) as archive:
            manifest = archive.read("AndroidManifest.xml")
    """

    path: Path
    _zip: zipfile.ZipFile
    members: list[MemberInfo] = field(default_factory=list)
    refusals: list[ArchiveRefusal] = field(default_factory=list)
    truncated: bool = False
    bytes_read: int = 0

    # ------------------------------------------------------------- lifecycle
    @classmethod
    def open(cls, path: Path) -> SafeArchive:
        """Open an archive and read its central directory."""
        if not path.is_file():
            raise ArchiveError(f"{path} is not a file")
        try:
            handle = zipfile.ZipFile(path)
        except zipfile.BadZipFile as exc:
            raise ArchiveError(f"{path.name} is not a readable ZIP archive: {exc}") from exc
        except OSError as exc:
            raise ArchiveError(f"{path.name} could not be opened: {exc}") from exc

        archive = cls(path=path, _zip=handle)
        try:
            archive._index()
        except Exception:
            handle.close()
            raise
        return archive

    def __enter__(self) -> SafeArchive:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._zip.close()

    # ------------------------------------------------------------- indexing
    def _index(self) -> None:
        infos = self._zip.infolist()
        if len(infos) > MAX_MEMBERS:
            self.truncated = True
            infos = infos[:MAX_MEMBERS]

        total_declared = 0
        for info in infos:
            mode = (info.external_attr >> 16) & 0xF000
            member = MemberInfo(
                name=info.filename,
                compressed_size=info.compress_size,
                uncompressed_size=info.file_size,
                is_directory=info.is_dir(),
                is_symlink=mode == _S_IFLNK,
                crc=info.CRC,
            )
            total_declared += member.uncompressed_size

            if refusal := self._refuse(member):
                self.refusals.append(ArchiveRefusal(name=member.name, reason=refusal))
                continue
            self.members.append(member)

        if total_declared > MAX_TOTAL_BYTES:
            self.refusals.append(
                ArchiveRefusal(
                    name="(archive)",
                    reason=(
                        f"the central directory declares {total_declared} uncompressed bytes, "
                        f"beyond the {MAX_TOTAL_BYTES}-byte session limit, so members are read "
                        "only until that limit is reached"
                    ),
                )
            )

    @staticmethod
    def _refuse(member: MemberInfo) -> str | None:
        """Why a member will not be read, or ``None`` if it may be."""
        name = member.name
        if member.is_symlink:
            return (
                "the member is a symbolic link; extracting it would read a file outside the "
                "archive, so it was refused"
            )
        if name.startswith("/") or name.startswith("\\"):
            return "the member name is an absolute path, which is a path-traversal attempt"
        if ".." in Path(name.replace("\\", "/")).parts:
            return "the member name escapes the archive root, which is a path-traversal attempt"
        if "\x00" in name:
            return "the member name contains a null byte"
        if member.is_directory:
            return None
        if member.uncompressed_size > MAX_MEMBER_BYTES:
            return (
                f"the member declares {member.uncompressed_size} uncompressed bytes, beyond "
                f"the {MAX_MEMBER_BYTES}-byte per-member limit"
            )
        if member.compressed_size > 1024 and member.compression_ratio > MAX_COMPRESSION_RATIO:
            return (
                f"the member's compression ratio is {member.compression_ratio:.0f}:1, beyond "
                f"the {MAX_COMPRESSION_RATIO}:1 limit, which is characteristic of a zip bomb"
            )
        return None

    # -------------------------------------------------------------- reading
    def has(self, name: str) -> bool:
        return any(m.name == name for m in self.members)

    def find(self, *, prefix: str = "", suffix: str = "") -> list[MemberInfo]:
        """Members matching a path prefix and/or filename suffix."""
        return [
            m
            for m in self.members
            if not m.is_directory
            and m.name.startswith(prefix)
            and (not suffix or m.name.lower().endswith(suffix.lower()))
        ]

    def read(self, name: str, *, limit: int | None = None) -> bytes:
        """Read one member, bounded.

        Raises :class:`ArchiveError` when the member is absent, was refused
        during indexing, or when the session's total byte budget is exhausted.
        """
        member = next((m for m in self.members if m.name == name), None)
        if member is None:
            refused = next((r for r in self.refusals if r.name == name), None)
            if refused is not None:
                raise ArchiveError(f"{name} was not read because {refused.reason}")
            raise ArchiveError(f"{name} is not present in {self.path.name}")
        return self.read_member(member, limit=limit)

    def read_member(self, member: MemberInfo, *, limit: int | None = None) -> bytes:
        cap = min(limit or MAX_MEMBER_BYTES, MAX_MEMBER_BYTES)
        remaining = MAX_TOTAL_BYTES - self.bytes_read
        if remaining <= 0:
            raise ArchiveError(
                f"the {MAX_TOTAL_BYTES}-byte read budget for this archive is exhausted, so "
                f"{member.name} was not read"
            )
        cap = min(cap, remaining)

        try:
            with self._zip.open(member.name) as stream:
                # Read one byte past the cap: if anything comes back, the
                # member is larger than its header claimed, which means the
                # central directory lied and the member is refused.
                data = stream.read(cap + 1)
        except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as exc:
            raise ArchiveError(f"{member.name} could not be decompressed: {exc}") from exc

        if len(data) > cap:
            raise ArchiveError(
                f"{member.name} decompressed to more than the {cap} bytes its header "
                "declared, so it was discarded as a decompression bomb"
            )
        self.bytes_read += len(data)
        return data

    def read_text(self, name: str, *, limit: int | None = None) -> str:
        return self.read(name, limit=limit).decode("utf-8", errors="replace")

    def stats(self) -> dict[str, Any]:
        return {
            "archive": self.path.name,
            "member_count": len(self.members),
            "refused_count": len(self.refusals),
            "refusals": [{"name": r.name, "reason": r.reason} for r in self.refusals[:50]],
            "index_truncated": self.truncated,
            "bytes_read": self.bytes_read,
        }


__all__ = [
    "MAX_COMPRESSION_RATIO",
    "MAX_MEMBER_BYTES",
    "MAX_TOTAL_BYTES",
    "ArchiveError",
    "ArchiveRefusal",
    "MemberInfo",
    "SafeArchive",
]
