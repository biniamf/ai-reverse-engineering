# Biniam Demissie
# Upload preflight: bounded binary/text classification for analyst confirmation.
"""Classify a bounded file prefix without relying on filename extensions."""
from __future__ import annotations

from dataclasses import dataclass

SNIFF_BYTES = 64 * 1024


@dataclass(frozen=True)
class FileClassification:
    kind: str  # known_binary | likely_text | raw_binary | empty
    format: str | None = None


_SIGNATURES = (
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/COFF"),
    (b"dex\n", "DEX"),
    (b"\x00asm", "WebAssembly"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat"),
    (b"PK\x03\x04", "ZIP/APK/JAR"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
)
_MACH_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}


def classify_file(contents: bytes) -> FileClassification:
    """Classify at most ``SNIFF_BYTES`` of already-bounded upload bytes."""
    if not contents:
        return FileClassification("empty")
    prefix = bytes(contents[:SNIFF_BYTES])
    for magic, label in _SIGNATURES:
        if prefix.startswith(magic):
            return FileClassification("known_binary", label)
    if prefix[:4] in _MACH_MAGICS:
        return FileClassification("known_binary", "Mach-O")

    # NUL/control/high bytes are strong binary evidence. UTF-8 text may contain
    # non-ASCII, so decode first and judge Unicode printability rather than
    # blindly treating every high byte as binary.
    if b"\x00" in prefix:
        return FileClassification("raw_binary")
    try:
        text = prefix.decode("utf-8")
    except UnicodeDecodeError:
        return FileClassification("raw_binary")
    if not text:
        return FileClassification("empty")
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    ratio = printable / len(text)
    if ratio >= 0.97:
        return FileClassification("likely_text", "UTF-8 text")
    return FileClassification("raw_binary")
