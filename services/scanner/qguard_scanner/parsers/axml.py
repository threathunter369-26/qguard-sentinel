"""Android binary XML (AXML) decoder.

``AndroidManifest.xml`` and the files under ``res/xml/`` in a compiled APK are
not text: they are Android's binary resource format, a sequence of chunks with
a shared string pool. Reading the manifest therefore means decoding that
format, and the manifest is where the most consequential Android findings live
— ``android:debuggable``, ``android:allowBackup``, exported components with no
permission, cleartext traffic, the network security configuration.

This decoder handles the subset needed to recover an element tree with
attributes: the string pool, the resource-map chunk (which supplies attribute
names for the system namespace), and the start/end element chunks. It is
written against a hostile input, so every offset and length is validated
against the buffer before use and every count is bounded.

Attribute values are resolved where that is possible without the full resource
table: inline strings, integers, booleans and floats decode directly. A value
that is a reference into ``resources.arsc`` cannot be resolved from the
manifest alone, so it is rendered as ``@0x7f0a0012`` rather than guessed at —
a check that depends on such a value reports that it could not be evaluated.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from qguard_scanner.parsers.android_attributes import attribute_name

# Chunk types from Android's ResourceTypes.h
_CHUNK_AXML_FILE = 0x0003
_CHUNK_STRING_POOL = 0x0001
_CHUNK_RESOURCE_MAP = 0x0180
_CHUNK_START_NAMESPACE = 0x0100
_CHUNK_END_NAMESPACE = 0x0101
_CHUNK_START_ELEMENT = 0x0102
_CHUNK_END_ELEMENT = 0x0103
_CHUNK_CDATA = 0x0104

# String pool flags
_FLAG_UTF8 = 1 << 8

# Res_value data types
_TYPE_NULL = 0x00
_TYPE_REFERENCE = 0x01
_TYPE_ATTRIBUTE = 0x02
_TYPE_STRING = 0x03
_TYPE_FLOAT = 0x04
_TYPE_DIMENSION = 0x05
_TYPE_FRACTION = 0x06
_TYPE_DYNAMIC_REFERENCE = 0x07
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12
_TYPE_INT_COLOR_ARGB8 = 0x1C
_TYPE_INT_COLOR_RGB8 = 0x1D
_TYPE_INT_COLOR_ARGB4 = 0x1E
_TYPE_INT_COLOR_RGB4 = 0x1F

#: Android's own namespace. Attributes in it are the ones security checks care
#: about, and their names come from the resource map rather than the pool.
ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"

#: Bounds. A manifest is a few hundred kilobytes; anything claiming more is
#: malformed or hostile.
MAX_STRINGS = 200_000
MAX_ELEMENTS = 200_000
MAX_ATTRIBUTES_PER_ELEMENT = 512
MAX_DEPTH = 256


class AxmlError(ValueError):
    """The document is not decodable Android binary XML."""


@dataclass(slots=True)
class AxmlAttribute:
    """One attribute on an element."""

    namespace: str | None
    name: str
    value: str
    raw_type: int
    raw_data: int

    @property
    def is_android(self) -> bool:
        return self.namespace == ANDROID_NAMESPACE

    @property
    def is_unresolved_reference(self) -> bool:
        """Whether the value is a resource reference this decoder cannot resolve."""
        return self.raw_type in (_TYPE_REFERENCE, _TYPE_ATTRIBUTE, _TYPE_DYNAMIC_REFERENCE)

    def as_bool(self) -> bool | None:
        """The value as a boolean, or ``None`` when it is not one."""
        if self.raw_type == _TYPE_INT_BOOLEAN:
            return self.raw_data != 0
        lowered = self.value.strip().lower()
        if lowered in ("true", "1"):
            return True
        if lowered in ("false", "0"):
            return False
        return None

    def as_int(self) -> int | None:
        if self.raw_type in (_TYPE_INT_DEC, _TYPE_INT_HEX):
            return self.raw_data
        try:
            return int(self.value.strip())
        except (TypeError, ValueError):
            return None


@dataclass(slots=True)
class AxmlElement:
    """One element in the decoded tree."""

    name: str
    namespace: str | None = None
    attributes: list[AxmlAttribute] = field(default_factory=list)
    children: list[AxmlElement] = field(default_factory=list)
    parent: AxmlElement | None = field(default=None, repr=False)

    # ------------------------------------------------------------- accessors
    def attribute(
        self, name: str, *, namespace: str | None = ANDROID_NAMESPACE
    ) -> AxmlAttribute | None:
        for attribute in self.attributes:
            if attribute.name != name:
                continue
            if namespace is None or attribute.namespace == namespace:
                return attribute
        return None

    def get(self, name: str, default: str | None = None) -> str | None:
        attribute = self.attribute(name)
        return attribute.value if attribute is not None else default

    def get_bool(self, name: str) -> bool | None:
        attribute = self.attribute(name)
        return attribute.as_bool() if attribute is not None else None

    def get_int(self, name: str) -> int | None:
        attribute = self.attribute(name)
        return attribute.as_int() if attribute is not None else None

    def find_all(self, name: str) -> list[AxmlElement]:
        """Every descendant with this tag name, depth first."""
        found: list[AxmlElement] = []
        for child in self.children:
            if child.name == name:
                found.append(child)
            found.extend(child.find_all(name))
        return found

    def find(self, name: str) -> AxmlElement | None:
        for child in self.children:
            if child.name == name:
                return child
        return None

    def path(self) -> str:
        parts: list[str] = []
        node: AxmlElement | None = self
        while node is not None:
            parts.append(node.name)
            node = node.parent
        return "/".join(reversed(parts))

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "attributes": {
                (f"android:{a.name}" if a.is_android else a.name): a.value for a in self.attributes
            },
            "children": [c.as_dict() for c in self.children],
        }


class _StringPool:
    """The document's shared string pool."""

    def __init__(self, data: bytes, offset: int, size: int) -> None:
        if size < 28:
            raise AxmlError("the string pool chunk is too small to be valid")
        # ResChunk_header: type (u16), headerSize (u16), size (u32).
        (header_size,) = struct.unpack_from("<H", data, offset + 2)
        count, style_count, flags, strings_start, styles_start = struct.unpack_from(
            "<IIIII", data, offset + 8
        )
        if count > MAX_STRINGS:
            raise AxmlError(f"the string pool declares {count} strings, beyond the supported limit")
        self._utf8 = bool(flags & _FLAG_UTF8)
        self._count = count
        self._cache: dict[int, str] = {}

        offsets_at = offset + header_size
        needed = offsets_at + count * 4
        if needed > offset + size or needed > len(data):
            raise AxmlError("the string pool's offset table extends past the end of the chunk")
        self._offsets = struct.unpack_from(f"<{count}I", data, offsets_at) if count else ()
        self._base = offset + strings_start
        self._data = data
        self._limit = min(offset + size, len(data))
        self._styles_start = styles_start
        self._style_count = style_count

    def __len__(self) -> int:
        return self._count

    def get(self, index: int) -> str:
        """The string at an index, or ``""`` when the index is out of range.

        An out-of-range index means the document is malformed. Returning an
        empty string keeps decoding going so the rest of the manifest can
        still be assessed, and the caller sees a missing name rather than an
        exception that loses the whole file.
        """
        if index < 0 or index >= self._count:
            return ""
        if index in self._cache:
            return self._cache[index]
        start = self._base + self._offsets[index]
        value = self._decode_utf8(start) if self._utf8 else self._decode_utf16(start)
        self._cache[index] = value
        return value

    def _decode_utf8(self, start: int) -> str:
        if start + 2 > self._limit:
            return ""
        cursor = start
        # Two lengths precede the bytes: character count then byte count,
        # each a one- or two-byte varint.
        for _ in range(2):
            if cursor >= self._limit:
                return ""
            first = self._data[cursor]
            cursor += 1
            if first & 0x80:
                if cursor >= self._limit:
                    return ""
                length = ((first & 0x7F) << 8) | self._data[cursor]
                cursor += 1
            else:
                length = first
        end = min(cursor + length, self._limit)
        return self._data[cursor:end].decode("utf-8", errors="replace")

    def _decode_utf16(self, start: int) -> str:
        if start + 2 > self._limit:
            return ""
        length = struct.unpack_from("<H", self._data, start)[0]
        cursor = start + 2
        if length & 0x8000:
            if cursor + 2 > self._limit:
                return ""
            low = struct.unpack_from("<H", self._data, cursor)[0]
            length = ((length & 0x7FFF) << 16) | low
            cursor += 2
        end = min(cursor + length * 2, self._limit)
        return self._data[cursor:end].decode("utf-16-le", errors="replace")


@dataclass(slots=True)
class AxmlDocument:
    """A decoded binary XML document."""

    root: AxmlElement
    warnings: list[str] = field(default_factory=list)
    string_count: int = 0

    def find_all(self, name: str) -> list[AxmlElement]:
        found = [self.root] if self.root.name == name else []
        found.extend(self.root.find_all(name))
        return found


def _format_value(value_type: int, data_value: int, string_index: int, pool: _StringPool) -> str:
    """Render a ``Res_value`` as text."""
    if value_type == _TYPE_STRING:
        return pool.get(string_index if string_index >= 0 else data_value)
    if value_type == _TYPE_INT_BOOLEAN:
        return "true" if data_value != 0 else "false"
    if value_type in (_TYPE_INT_DEC,):
        # Values are stored unsigned; reinterpret so a negative stays negative.
        return str(struct.unpack("<i", struct.pack("<I", data_value))[0])
    if value_type == _TYPE_INT_HEX:
        return f"0x{data_value:08x}"
    if value_type == _TYPE_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", data_value))[0])
    if value_type in (_TYPE_REFERENCE, _TYPE_DYNAMIC_REFERENCE):
        # A reference into resources.arsc. It is rendered, not resolved: this
        # decoder does not read the resource table, and inventing a value
        # would make a check appear to have evaluated something it did not.
        return f"@0x{data_value:08x}"
    if value_type == _TYPE_ATTRIBUTE:
        return f"?0x{data_value:08x}"
    if value_type == _TYPE_NULL:
        return ""
    if value_type in (
        _TYPE_INT_COLOR_ARGB8,
        _TYPE_INT_COLOR_RGB8,
        _TYPE_INT_COLOR_ARGB4,
        _TYPE_INT_COLOR_RGB4,
    ):
        return f"#{data_value:08x}"
    if value_type in (_TYPE_DIMENSION, _TYPE_FRACTION):
        return f"0x{data_value:08x}"
    return f"0x{data_value:08x}"


def parse_axml(data: bytes) -> AxmlDocument:
    """Decode Android binary XML into an element tree.

    Raises :class:`AxmlError` when the buffer is not AXML or is too malformed
    to yield a tree, so the caller can report the real reason instead of
    treating an undecodable manifest as an empty one.
    """
    if len(data) < 8:
        raise AxmlError("the buffer is too short to be Android binary XML")

    magic, _header_size, file_size = struct.unpack_from("<HHI", data, 0)
    if magic != _CHUNK_AXML_FILE:
        if data.lstrip()[:1] == b"<":
            raise AxmlError(
                "the file is plain-text XML, not Android binary XML — decode it as text"
            )
        raise AxmlError(f"the file does not start with the AXML chunk magic (found 0x{magic:04x})")
    limit = min(file_size, len(data))
    if limit < 8:
        raise AxmlError("the AXML header declares a file size smaller than the header itself")

    warnings: list[str] = []
    pool: _StringPool | None = None
    resource_ids: tuple[int, ...] = ()
    namespaces: dict[str, str] = {}
    root: AxmlElement | None = None
    current: AxmlElement | None = None
    depth = 0
    elements_seen = 0

    cursor = 8
    while cursor + 8 <= limit:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, cursor)
        if chunk_size < 8 or cursor + chunk_size > limit:
            warnings.append(
                f"A chunk at offset {cursor} declares an invalid size ({chunk_size}); "
                "decoding stopped there, so any later content was not assessed."
            )
            break

        if chunk_type == _CHUNK_STRING_POOL:
            pool = _StringPool(data, cursor, chunk_size)
        elif chunk_type == _CHUNK_RESOURCE_MAP:
            count = min((chunk_size - header_size) // 4, MAX_STRINGS)
            if count > 0:
                resource_ids = struct.unpack_from(f"<{count}I", data, cursor + header_size)
        elif chunk_type == _CHUNK_START_NAMESPACE:
            if pool is None:
                raise AxmlError("a namespace chunk appeared before the string pool")
            prefix_index, uri_index = struct.unpack_from("<iI", data, cursor + header_size + 8)
            namespaces[pool.get(uri_index)] = pool.get(prefix_index)
        elif chunk_type == _CHUNK_START_ELEMENT:
            if pool is None:
                raise AxmlError("an element chunk appeared before the string pool")
            elements_seen += 1
            if elements_seen > MAX_ELEMENTS:
                warnings.append(
                    f"The document contains more than {MAX_ELEMENTS} elements; decoding "
                    "stopped there, so the remainder was not assessed."
                )
                break
            element, element_warnings = _decode_start_element(
                data, cursor, header_size, chunk_size, pool, resource_ids
            )
            warnings.extend(element_warnings)
            if root is None:
                root = element
                current = element
            elif current is not None:
                element.parent = current
                current.children.append(element)
                current = element
            depth += 1
            if depth > MAX_DEPTH:
                raise AxmlError(f"the element tree is nested beyond {MAX_DEPTH} levels")
        elif chunk_type == _CHUNK_END_ELEMENT:
            depth -= 1
            if current is not None and current.parent is not None:
                current = current.parent
        elif chunk_type in (_CHUNK_END_NAMESPACE, _CHUNK_CDATA):
            pass

        cursor += chunk_size

    if pool is None:
        raise AxmlError("the document contains no string pool, so no name could be decoded")
    if root is None:
        raise AxmlError("the document contains no elements")

    return AxmlDocument(root=root, warnings=warnings, string_count=len(pool))


def _decode_start_element(
    data: bytes,
    cursor: int,
    header_size: int,
    chunk_size: int,
    pool: _StringPool,
    resource_ids: tuple[int, ...],
) -> tuple[AxmlElement, list[str]]:
    """Decode one start-element chunk and its attributes."""
    warnings: list[str] = []
    body = cursor + header_size
    if body + 20 > cursor + chunk_size:
        raise AxmlError(f"the element chunk at offset {cursor} is truncated")

    namespace_index, name_index = struct.unpack_from("<iI", data, body)
    attribute_start, attribute_size, attribute_count = struct.unpack_from("<HHH", data, body + 8)
    name = pool.get(name_index)
    namespace = pool.get(namespace_index) if namespace_index >= 0 else None
    element = AxmlElement(name=name, namespace=namespace or None)

    if attribute_count > MAX_ATTRIBUTES_PER_ELEMENT:
        warnings.append(
            f"The element {name!r} declares {attribute_count} attributes; only the first "
            f"{MAX_ATTRIBUTES_PER_ELEMENT} were decoded."
        )
        attribute_count = MAX_ATTRIBUTES_PER_ELEMENT
    if attribute_size < 20:
        warnings.append(
            f"The element {name!r} declares an attribute stride of {attribute_size} bytes, "
            "which is too small to be valid; its attributes were not decoded."
        )
        return element, warnings

    base = body + attribute_start
    for index in range(attribute_count):
        at = base + index * attribute_size
        if at + 20 > cursor + chunk_size:
            warnings.append(
                f"The attributes of {name!r} extend past the end of the chunk; "
                f"{attribute_count - index} were not decoded."
            )
            break
        (
            attr_namespace_index,
            attr_name_index,
            attr_raw_value_index,
            typed_value,
        ) = struct.unpack_from("<iiiI", data, at)
        value_type = (typed_value >> 24) & 0xFF
        data_value = struct.unpack_from("<I", data, at + 16)[0]

        attr_name = pool.get(attr_name_index)
        if not attr_name and 0 <= attr_name_index < len(resource_ids):
            # A compiled manifest references system attributes by resource ID
            # and leaves the pool entry empty. The resource map supplies the
            # ID; an ID this decoder does not know is rendered as hex rather
            # than guessed, so a check never reads the wrong attribute.
            resource_id = resource_ids[attr_name_index]
            attr_name = attribute_name(resource_id) or f"0x{resource_id:08x}"

        attr_namespace = pool.get(attr_namespace_index) if attr_namespace_index >= 0 else None
        element.attributes.append(
            AxmlAttribute(
                namespace=attr_namespace or None,
                name=attr_name,
                value=_format_value(value_type, data_value, attr_raw_value_index, pool),
                raw_type=value_type,
                raw_data=data_value,
            )
        )

    return element, warnings


__all__ = [
    "ANDROID_NAMESPACE",
    "AxmlAttribute",
    "AxmlDocument",
    "AxmlElement",
    "AxmlError",
    "parse_axml",
]
