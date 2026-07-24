# Biniam Demissie
# Cache-busting: a stable ASSET_VERSION computed once at process startup.
"""Deterministic asset version for cache-busting static/template URLs."""
from __future__ import annotations

import hashlib
import os

# webui/ package directory (this file's directory), used only to build
# *relative* paths for hashing -- never embedded in the version string.
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_STATIC_DIR = os.path.join(_BASE_DIR, "static")
_TEMPLATES_DIR = os.path.join(_BASE_DIR, "templates")

# Directories that are never served to a browser (frontend unit tests,
# bytecode caches) and so must not influence the asset version -- editing a
# test file should never bust the cache for shipped assets.
_EXCLUDED_DIR_NAMES = frozenset({"tests", "__pycache__"})

# Length of the truncated hex digest used when no APP_VERSION is supplied.
# 12 hex chars (48 bits) is far more than enough to avoid accidental
# collisions between two different frontend builds while keeping URLs short.
_HASH_PREFIX_LEN = 12


def _iter_hashable_files():
    """Yield (relative_path, absolute_path) for every file to hash."""
    for root_dir, label in ((_STATIC_DIR, "static"), (_TEMPLATES_DIR, "templates")):
        if not os.path.isdir(root_dir):
            continue
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Prune excluded directories in-place (and sort remaining ones)
            # so os.walk never descends into them and traversal order is
            # deterministic across platforms.
            dirnames[:] = sorted(d for d in dirnames if d not in _EXCLUDED_DIR_NAMES)
            for filename in sorted(filenames):
                abs_path = os.path.join(dirpath, filename)
                rel_within_root = os.path.relpath(abs_path, root_dir)
                # Normalize to forward slashes for a platform-independent
                # relative path used only as a hash input (never exposed).
                rel_path = f"{label}/{rel_within_root.replace(os.sep, '/')}"
                yield rel_path, abs_path


def _compute_hash_version() -> str:
    """SHA-256 over every (relative_path, content) pair, sorted by path."""
    digest = hashlib.sha256()
    for rel_path, abs_path in sorted(_iter_hashable_files(), key=lambda item: item[0]):
        with open(abs_path, "rb") as fh:
            content = fh.read()
        digest.update(rel_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()[:_HASH_PREFIX_LEN]


def _compute_asset_version() -> str:
    override = os.environ.get("APP_VERSION", "").strip()
    if override:
        return override
    return _compute_hash_version()


ASSET_VERSION = _compute_asset_version()
