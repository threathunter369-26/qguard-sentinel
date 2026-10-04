"""Dalvik executable (DEX) reader.

An APK's compiled code lives in ``classes.dex``. Full bytecode analysis needs
a decompiler; a great deal of what matters for a mobile security assessment
does not. The DEX format carries three tables that can be read directly and
that answer most questions precisely:

* **The string pool** — every string literal in the application, which is
  where hardcoded credentials, API endpoints, SQL fragments and debug messages
  are found.
* **The type table** — every class the application defines or references, so
  the presence of a library or a dangerous base class is a fact rather than an
  inference from a filename.
* **The method reference table** — every method the application calls,
  qualified by its declaring class. ``Ljavax/net/ssl/SSLContext;->init`` being
  present is direct evidence that the application configures TLS itself, which
  is the signal a check needs.

A method *reference* means the call site exists somewhere in the application.
It does not prove the call executes, and findings derived from it say so
rather than claiming confirmation. That is the honest reading of what this
table supports, and it is still far stronger than matching on strings alone.

The reader validates every offset and count against the buffer. A DEX file is
untrusted input: a header claiming four billion strings must be refused, not
allocated for.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

#: Accepted DEX magic values, by format version.
DEX_MAGICS: dict[bytes, str] = {
    b"dex\n035\x00": "035",
    b"dex\n036\x00": "036",
    b"dex\n037\x00": "037",
    b"dex\n038\x00": "038",
    b"dex\n039\x00": "039",
    b"dex\n040\x00": "040",
}

_HEADER_SIZE = 0x70
_EXPECTED_ENDIAN = 0x12345678

#: Bounds for untrusted input.
MAX_STRINGS = 2_000_000
MAX_TYPES = 500_000
MAX_METHODS = 2_000_000
MAX_STRING_BYTES = 64 * 1024


class DexError(ValueError):
    """The buffer is not a readable DEX file."""


@dataclass(slots=True)
class MethodReference:
    """One entry in the method reference table."""

    #: ``Ljava/lang/String;`` style descriptor of the declaring class.
    class_descriptor: str
    name: str

    @property
    def class_name(self) -> str:
        """The declaring class in dotted form, e.g. ``java.lang.String``."""
        descriptor = self.class_descriptor
        if descriptor.startswith("L") and descriptor.endswith(";"):
            return descriptor[1:-1].replace("/", ".")
        return descriptor

    @property
    def signature(self) -> str:
        """A stable identifier, e.g. ``Ljava/lang/String;->valueOf``."""
        return f"{self.class_descriptor}->{self.name}"


@dataclass(slots=True)
class DexFile:
    """The tables read from one DEX file."""

    version: str
    strings: list[str] = field(default_factory=list)
    type_descriptors: list[str] = field(default_factory=list)
    methods: list[MethodReference] = field(default_factory=list)
    defined_class_descriptors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False

    _method_index: frozenset[str] = field(default_factory=frozenset, repr=False)
    _type_index: frozenset[str] = field(default_factory=frozenset, repr=False)

    def __post_init__(self) -> None:
        if not self._method_index:
            self._method_index = frozenset(m.signature for m in self.methods)
        if not self._type_index:
            self._type_index = frozenset(self.type_descriptors)

    # ------------------------------------------------------------- lookups
    def calls(self, signature: str) -> bool:
        """Whether a method reference with this ``Lclass;->name`` exists."""
        return signature in self._method_index

    def references_type(self, descriptor: str) -> bool:
        return descriptor in self._type_index

    def methods_on(self, class_descriptor: str) -> list[MethodReference]:
        return [m for m in self.methods if m.class_descriptor == class_descriptor]

    def stats(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "string_count": len(self.strings),
            "type_count": len(self.type_descriptors),
            "method_reference_count": len(self.methods),
            "defined_class_count": len(self.defined_class_descriptors),
            "truncated": self.truncated,
            "warnings": self.warnings,
        }


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Read an unsigned LEB128 value, returning ``(value, next_offset)``."""
    result = 0
    shift = 0
    limit = len(data)
    while offset < limit:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7
        if shift > 28:
            # DEX ULEB128 values are at most five bytes.
            raise DexError(f"a ULEB128 value at offset {offset} is longer than five bytes")
    raise DexError("a ULEB128 value runs past the end of the buffer")


def _decode_mutf8(data: bytes, offset: int, utf16_units: int) -> tuple[str, int]:
    """Decode a NUL-terminated MUTF-8 string.

    Java's modified UTF-8 encodes U+0000 as two bytes and supplementary
    characters as a surrogate pair of three-byte sequences. Python's UTF-8
    decoder rejects both, so the bytes are decoded through ``utf-16`` surrogate
    handling instead of being silently mangled.
    """
    end = data.find(b"\x00", offset)
    if end == -1:
        end = min(offset + MAX_STRING_BYTES, len(data))
    if end - offset > MAX_STRING_BYTES:
        end = offset + MAX_STRING_BYTES
    raw = data[offset:end]

    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Fall back to surrogate-aware decoding, then repair pairs.
        decoded = raw.decode("utf-8", errors="surrogatepass")
    try:
        decoded = decoded.encode("utf-16", "surrogatepass").decode("utf-16")
    except UnicodeError:
        decoded = raw.decode("utf-8", errors="replace")

    # The declared length is in UTF-16 code units and is advisory here; a
    # mismatch means the file is malformed, which the caller can note.
    if utf16_units and len(decoded) > utf16_units * 2 + 8:
        decoded = decoded[: utf16_units * 2]
    return decoded, end + 1


def parse_dex(data: bytes, *, read_methods: bool = True) -> DexFile:
    """Read the string, type and method tables from a DEX buffer."""
    if len(data) < _HEADER_SIZE:
        raise DexError("the buffer is shorter than a DEX header")

    magic = data[:8]
    version = DEX_MAGICS.get(magic)
    if version is None:
        raise DexError(f"the buffer does not begin with a known DEX magic (found {magic!r})")

    endian_tag = struct.unpack_from("<I", data, 40)[0]
    if endian_tag != _EXPECTED_ENDIAN:
        raise DexError(
            f"the DEX endian tag is 0x{endian_tag:08x}; only little-endian files are supported"
        )

    (
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        _proto_ids_size,
        _proto_ids_off,
        _field_ids_size,
        _field_ids_off,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
    ) = struct.unpack_from("<12I", data, 56)

    warnings: list[str] = []
    truncated = False

    def bounded(count: int, ceiling: int, label: str) -> int:
        nonlocal truncated
        if count > ceiling:
            warnings.append(
                f"The DEX header declares {count} {label}, beyond the {ceiling} supported; "
                f"the first {ceiling} were read and the remainder was not analysed."
            )
            truncated = True
            return ceiling
        return count

    string_count = bounded(string_ids_size, MAX_STRINGS, "strings")
    type_count = bounded(type_ids_size, MAX_TYPES, "types")
    method_count = bounded(method_ids_size, MAX_METHODS, "method references")

    # ------------------------------------------------------------- strings
    strings: list[str] = []
    if string_count:
        table_end = string_ids_off + string_count * 4
        if table_end > len(data):
            raise DexError("the string id table extends past the end of the buffer")
        offsets = struct.unpack_from(f"<{string_count}I", data, string_ids_off)
        malformed = 0
        for offset in offsets:
            if offset >= len(data):
                malformed += 1
                strings.append("")
                continue
            try:
                units, cursor = _read_uleb128(data, offset)
                value, _ = _decode_mutf8(data, cursor, units)
            except DexError:
                malformed += 1
                strings.append("")
                continue
            strings.append(value)
        if malformed:
            warnings.append(
                f"{malformed} of {string_count} string entries pointed outside the buffer or "
                "were malformed and were read as empty."
            )

    # --------------------------------------------------------------- types
    type_descriptors: list[str] = []
    if type_count:
        table_end = type_ids_off + type_count * 4
        if table_end > len(data):
            warnings.append(
                "The type id table extends past the end of the buffer; types were not read."
            )
            truncated = True
        else:
            indices = struct.unpack_from(f"<{type_count}I", data, type_ids_off)
            type_descriptors = [strings[i] if i < len(strings) else "" for i in indices]

    # ------------------------------------------------------------- methods
    methods: list[MethodReference] = []
    if read_methods and method_count:
        table_end = method_ids_off + method_count * 8
        if table_end > len(data):
            warnings.append(
                "The method id table extends past the end of the buffer; method references "
                "were not read, so checks that depend on them did not run."
            )
            truncated = True
        else:
            raw = struct.unpack_from(f"<{method_count * 4}H", data, method_ids_off)
            for index in range(method_count):
                class_idx = raw[index * 4]
                # name_idx is a uint32 spanning two of the shorts read above.
                name_idx = raw[index * 4 + 2] | (raw[index * 4 + 3] << 16)
                methods.append(
                    MethodReference(
                        class_descriptor=(
                            type_descriptors[class_idx] if class_idx < len(type_descriptors) else ""
                        ),
                        name=strings[name_idx] if name_idx < len(strings) else "",
                    )
                )

    # ------------------------------------------------------- defined classes
    defined: list[str] = []
    if class_defs_size:
        count = min(class_defs_size, MAX_TYPES)
        table_end = class_defs_off + count * 32
        if table_end <= len(data):
            for index in range(count):
                class_idx = struct.unpack_from("<I", data, class_defs_off + index * 32)[0]
                if class_idx < len(type_descriptors):
                    defined.append(type_descriptors[class_idx])
        else:
            warnings.append(
                "The class definition table extends past the end of the buffer; defined "
                "classes were not read."
            )
            truncated = True

    return DexFile(
        version=version,
        strings=strings,
        type_descriptors=type_descriptors,
        methods=methods,
        defined_class_descriptors=defined,
        warnings=warnings,
        truncated=truncated,
    )


def merge(files: list[DexFile]) -> DexFile:
    """Combine several DEX files from one application into a single view.

    A multi-DEX application splits its classes across ``classes.dex``,
    ``classes2.dex`` and so on. Checks apply to the application, not to one
    DEX, so the tables are merged before any check runs.
    """
    if not files:
        raise DexError("no DEX files were supplied")
    merged = DexFile(version=files[0].version)
    seen_methods: set[str] = set()
    seen_types: set[str] = set()
    for dex in files:
        merged.strings.extend(dex.strings)
        merged.warnings.extend(dex.warnings)
        merged.truncated = merged.truncated or dex.truncated
        for descriptor in dex.type_descriptors:
            if descriptor not in seen_types:
                seen_types.add(descriptor)
                merged.type_descriptors.append(descriptor)
        for method in dex.methods:
            if method.signature not in seen_methods:
                seen_methods.add(method.signature)
                merged.methods.append(method)
        merged.defined_class_descriptors.extend(dex.defined_class_descriptors)
    merged._method_index = frozenset(seen_methods)
    merged._type_index = frozenset(seen_types)
    return merged


__all__ = [
    "DEX_MAGICS",
    "DexError",
    "DexFile",
    "MethodReference",
    "merge",
    "parse_dex",
]
