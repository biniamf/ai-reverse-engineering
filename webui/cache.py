# Biniam Demissie
"""A tiny, dependency-free bounded cache."""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Optional


class BoundedTTLCache:
    def __init__(self, *, ttl: float = 300.0, max_entries: int = 128):
        self.ttl = float(ttl)
        self.max_entries = int(max_entries)
        self._store: "OrderedDict[str, tuple]" = OrderedDict()
        # Guards every read/write of self._store so concurrent threads (one
        # per in-flight request, under gunicorn's gthread worker class) never
        # observe or produce a torn OrderedDict.
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, stored_at = entry
            if (time.monotonic() - stored_at) > self.ttl:
                self._store.pop(key, None)
                return None
            self._store.move_to_end(key)
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if self.max_entries <= 0:
                return
            self._store[key] = (value, time.monotonic())
            self._store.move_to_end(key)
            while len(self._store) > self.max_entries:
                self._store.popitem(last=False)

    def delete(self, key: str) -> None:
        """Drop a single key if present (e.g. when its job is deleted)."""
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:  # pragma: no cover - trivial
        with self._lock:
            return len(self._store)
