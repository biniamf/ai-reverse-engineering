# Biniam Demissie
"""Atomic, validated chat-history storage."""
from __future__ import annotations

import json
import os
import tempfile
import time
from typing import List, Optional
from uuid import uuid4

from validation import validate_job_id, validate_thread_id

# Reserved sentinel meaning the default thread (thread_id ``None`` -- the
# unchanged ``<job_id>.json`` file). Never used as a sub-thread filename.
MAIN_THREAD_ID = "main"

_INDEX_FILENAME = "threads.json"

_DEFAULT_MAX_BYTES = 8 * 1024 * 1024
_MAX_THREADS_PER_JOB = 128


class ChatStore:
    """Validated, atomic, bounded chat-history storage."""

    def __init__(self, base_dir: str, *, max_bytes: int = _DEFAULT_MAX_BYTES):
        if not isinstance(base_dir, str) or not base_dir.strip():
            raise ValueError("base_dir must be a non-empty path")
        self.base_dir = base_dir
        self.max_bytes = int(max_bytes)
        os.makedirs(self.base_dir, exist_ok=True)
        try:
            os.chmod(self.base_dir, 0o700)
        except OSError:  # pragma: no cover - platform dependent (e.g. Windows)
            pass

    def _path(self, job_id: str, thread_id: Optional[str] = None) -> str:
        # Validate before either id can influence a filesystem path.
        safe_id = validate_job_id(job_id)
        if thread_id is None:
            # The default "main" thread keeps the exact legacy path/behavior.
            return os.path.join(self.base_dir, f"{safe_id}.json")
        safe_thread = validate_thread_id(thread_id)
        return os.path.join(self.base_dir, safe_id, f"{safe_thread}.json")

    def _thread_dir(self, job_id: str) -> str:
        safe_id = validate_job_id(job_id)
        return os.path.join(self.base_dir, safe_id)

    def _ensure_thread_dir(self, job_id: str) -> str:
        """Lazily create the per-job sub-thread directory (chmod 0700)."""
        directory = self._thread_dir(job_id)
        os.makedirs(directory, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:  # pragma: no cover - platform dependent (e.g. Windows)
            pass
        return directory

    def _index_path(self, job_id: str) -> str:
        return os.path.join(self._thread_dir(job_id), _INDEX_FILENAME)

    def load(self, job_id: str, thread_id: Optional[str] = None) -> List[dict]:
        """Return the stored history list, or ``[]`` on any recoverable fault."""
        path = self._path(job_id, thread_id)
        try:
            if not os.path.exists(path):
                return []
            # Bounded read: refuse to load a file larger than the ceiling.
            if os.path.getsize(path) > self.max_bytes:
                return []
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return []
        # Legacy + defensive: only a JSON list is a valid transcript.
        if not isinstance(data, list):
            return []
        return data

    def save(
        self, job_id: str, messages: List[dict], thread_id: Optional[str] = None
    ) -> None:
        """Atomically persist ``messages`` for ``job_id`` (optionally a thread)."""
        if not isinstance(messages, list):
            raise ValueError("messages must be a list")
        if thread_id is not None:
            self._ensure_thread_dir(job_id)
        path = self._path(job_id, thread_id)
        self._atomic_write_json(path, messages, prefix=".chat-")

    def _atomic_write_json(self, path: str, data, *, prefix: str) -> None:
        """Atomic temp-write + ``os.replace`` of a JSON document at ``path``."""
        directory = os.path.dirname(path) or "."
        fd, tmp_path = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:  # pragma: no cover - platform dependent
                pass
            os.replace(tmp_path, path)
        except BaseException:
            # Never leave a stray temp file behind on failure.
            try:
                os.unlink(tmp_path)
            except OSError:  # pragma: no cover - already gone
                pass
            raise

    # ------------------------------------------------------------------ # Thread index
    # (metadata source of truth; per-thread files stay pure message lists). The main
    # thread is synthesized, never stored here.
    def _load_index(self, job_id: str) -> List[dict]:
        """Return the sub-thread metadata list, or ``[]`` on any fault."""
        path = self._index_path(job_id)
        try:
            if not os.path.exists(path):
                return []
            if os.path.getsize(path) > self.max_bytes:
                return []
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return []
        if not isinstance(data, list):
            return []
        valid: List[dict] = []
        for entry in data[:_MAX_THREADS_PER_JOB]:
            if not isinstance(entry, dict):
                continue
            try:
                thread_id = validate_thread_id(entry.get("thread_id"))
                parent = entry.get("parent_thread_id")
                parent = validate_thread_id(parent) if parent else None
            except (TypeError, ValueError):
                continue
            valid.append(
                {
                    **entry,
                    "thread_id": thread_id,
                    "parent_thread_id": parent,
                }
            )
        return valid

    def _write_index(self, job_id: str, index: List[dict]) -> None:
        self._ensure_thread_dir(job_id)
        self._atomic_write_json(self._index_path(job_id), index, prefix=".threads-")

    def _thread_message_count(self, job_id: str, thread_id: Optional[str]) -> int:
        try:
            return len(self.load(job_id, thread_id))
        except Exception:  # pragma: no cover - defensive (malformed index id)
            return 0

    def list_threads(self, job_id: str) -> List[dict]:
        """Return this job's threads: the main thread first, then sub-threads."""
        threads = [
            {
                "thread_id": MAIN_THREAD_ID,
                "title": "Main",
                "parent_thread_id": None,
                "created_at": None,
                "updated_at": None,
                "message_count": self._thread_message_count(job_id, None),
            }
        ]
        for entry in self._load_index(job_id):
            tid = entry.get("thread_id")
            threads.append(
                {
                    "thread_id": tid,
                    "title": entry.get("title", ""),
                    "parent_thread_id": entry.get("parent_thread_id"),
                    "created_at": entry.get("created_at"),
                    "updated_at": entry.get("updated_at"),
                    "message_count": self._thread_message_count(job_id, tid),
                }
            )
        return threads

    def get_thread(self, job_id: str, thread_id: str) -> Optional[dict]:
        """Return one sub-thread's index record, or ``None`` if absent."""
        if thread_id == MAIN_THREAD_ID:
            return None
        safe_thread = validate_thread_id(thread_id)
        for entry in self._load_index(job_id):
            if entry.get("thread_id") == safe_thread:
                return dict(entry)
        return None

    def create_thread(
        self, job_id: str, *, title: str, parent_thread_id: Optional[str] = None
    ) -> dict:
        """Mint a new sub-thread record and persist it into the index."""
        parent = None
        if parent_thread_id is not None and parent_thread_id != MAIN_THREAD_ID:
            parent = validate_thread_id(parent_thread_id)
            if self.get_thread(job_id, parent) is None:
                raise ValueError("parent thread not found")
        index = self._load_index(job_id)
        if len(index) >= _MAX_THREADS_PER_JOB:
            raise ValueError("thread limit reached for this job")
        thread_id = uuid4().hex
        now = time.time()
        entry = {
            "thread_id": thread_id,
            "title": title,
            "parent_thread_id": parent,
            "created_at": now,
            "updated_at": now,
        }
        index.append(entry)
        self._write_index(job_id, index)
        return {**entry, "message_count": 0}

    def rename_thread(self, job_id: str, thread_id: str, *, title: str) -> Optional[dict]:
        """Rename a sub-thread in the index; return the record or ``None``."""
        safe_thread = validate_thread_id(thread_id)
        index = self._load_index(job_id)
        for entry in index:
            if entry.get("thread_id") == safe_thread:
                entry["title"] = title
                entry["updated_at"] = time.time()
                self._write_index(job_id, index)
                return {
                    **entry,
                    "message_count": self._thread_message_count(job_id, safe_thread),
                }
        return None
