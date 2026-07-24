# Biniam Demissie
"""Typed client for the Ghidra analysis service."""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import requests

_ALLOWED_SCHEMES = ("http", "https")

CAP_V1 = "v1"
CAP_LEGACY = "legacy"
CAP_UNKNOWN = "unknown"

# Terminal job states: the WebUI stops polling on every one of these, not only
# ``done``/``failed`` (see GHIDRA_V1_INTEGRATION.md section 5).
TERMINAL_JOB_STATES = ("done", "failed", "cancelled", "interrupted")

# The service advertises optional features under two objects that may both be present,
# one, or neither (see GHIDRA_V1_INTEGRATION.md sections 1 and 15): * ``capabilities``
# -- the original object keyed by *service* names (``graph_neighborhood``.
_SERVICE_TO_WEBUI = {
    "graph_neighborhood": "callgraph",
    "string_references": "string_references",
    "multipart_upload": "multipart_upload",
    "annotations": "annotations",
    "cancellation": "cancellation",
    "deduplication": "deduplication",
    "export": "export",
    "hexdump": "hexdump",
    "summary": "summary",
    "types": "types",
    "globals": "globals",
    # The security-index / attack-surface capability is advertised under the service-
    # vocabulary name ``security_index`` in the ``capabilities`` object and under the
    # WebUI-vocabulary name ``attack_surface`` in the ``features`` object.
    "security_index": "attack_surface",
}

_WEBUI_FEATURE_KEYS = (
    "summary",
    "types",
    "globals",
    "annotations",
    "callgraph",
    "multipart_upload",
    "hexdump",
    "export",
    "cancellation",
    "deduplication",
    "string_references",
    "attack_surface",
)


def normalize_capabilities(payload: Any) -> Dict[str, bool]:
    """Merge the ``features`` and ``capabilities`` objects into one WebUI map."""
    merged: Dict[str, bool] = {}
    if not isinstance(payload, dict):
        return merged

    def absorb(raw: Any, translate: bool) -> None:
        if isinstance(raw, dict):
            pairs = list(raw.items())
        elif isinstance(raw, list):
            pairs = [(str(name), True) for name in raw]
        else:
            return
        for name, value in pairs:
            key = _SERVICE_TO_WEBUI.get(name, name) if translate else name
            if key in _WEBUI_FEATURE_KEYS:
                merged[key] = bool(value) or merged.get(key, False)

    absorb(payload.get("capabilities"), translate=True)
    absorb(payload.get("features"), translate=False)
    # A payload that is itself a flat WebUI-named map (no wrapper object) is
    # also tolerated for forward compatibility.
    if not merged and not any(
        k in payload for k in ("capabilities", "features")
    ):
        absorb(payload, translate=True)
    return merged


def _addr_of(item: Any) -> Optional[str]:
    """Extract an address string from a legacy xref list item."""
    if isinstance(item, str):
        text = item.strip()
        return text or None
    if isinstance(item, dict):
        for key in ("address", "addr", "to", "from", "target"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _addr_list(data: Any, *keys: str) -> list:
    if not isinstance(data, dict):
        return []
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            out = []
            for item in value:
                addr = _addr_of(item)
                if addr is not None:
                    out.append(addr)
            return out
    return []


def _add_node(nodes: set, addr: str, max_nodes: int) -> bool:
    if addr in nodes:
        return True
    if len(nodes) >= max_nodes:
        return False
    nodes.add(addr)
    return True


def _add_edge(edges: list, seen: set, src: str, dst: str, max_edges: int) -> bool:
    key = (src, dst)
    if key in seen:
        return True
    if len(edges) >= max_edges:
        return False
    seen.add(key)
    edges.append({"from": src, "to": dst})
    return True


# --------------------------------------------------------------------------- # Job
# redaction (module-level, pure, unit-testable).
_JOB_SAFE_FIELDS = frozenset(
    {
        "job_id",
        "status",
        "filename",
        "created_at",
        "started_at",
        "completed_at",
        "sha256",
        "persist",
        "cache_hit",
        "reused_job_id",
        "project_available",
        "analyzer_version",
        "artifact_schema_version",
        "schema_version",
        "progress",
    }
)

# Error codes the service is contracted to expose (section 5). Only a value in
# this whitelist is forwarded; anything else becomes the generic sentinel so a
# leaked internal code/string never reaches the browser.
_JOB_SAFE_ERROR_CODES = frozenset(
    {
        "timeout",
        "process_error",
        "export_error",
        "internal_error",
        "cancelled",
        "service_restart",
    }
)

# A user-safe error message is bounded and stripped of anything path/URL-like.
_MAX_SAFE_MESSAGE = 200


def _looks_sensitive(text: str) -> bool:
    """Heuristic: does a short message contain a path/URL/host that must not"""
    lowered = text.lower()
    if "://" in lowered:  # any URL scheme (internal service URL, etc.)
        return True
    if "/" in text or "\\" in text:  # filesystem path separators
        return True
    if lowered.startswith("traceback"):
        return True
    if ".py" in lowered and "line " in lowered:  # stack-trace-like text
        return True
    return False


def redact_job(job: Any) -> Dict[str, Any]:
    """Return an allow-listed, redacted copy of a job/status record."""
    if not isinstance(job, dict):
        return {}
    out: Dict[str, Any] = {}
    for key in _JOB_SAFE_FIELDS:
        if key in job:
            out[key] = job[key]
    code = job.get("error_code")
    if isinstance(code, str) and code in _JOB_SAFE_ERROR_CODES:
        out["error_code"] = code
    message = job.get("message")
    if isinstance(message, str) and message:
        trimmed = message.strip()[:_MAX_SAFE_MESSAGE]
        if trimmed and not _looks_sensitive(trimmed):
            out["message"] = trimmed
    return out


class GhidraClientError(Exception):
    """Normalized error for any Ghidra client failure."""

    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        code: str = "error",
    ):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        # Optional structured envelope (e.g. the stable security-index
        # unavailable body) that a route may forward to the browser. Always
        # present so callers can read it without hasattr checks.
        self.envelope: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"error": self.message, "code": self.code, "status": self.status}


class GhidraClient:
    """A typed, timed wrapper around the Ghidra HTTP service."""

    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        *,
        connect_timeout: float = 5.0,
        read_timeout: float = 30.0,
        max_response_bytes: int = 25 * 1024 * 1024,
        capability_cache_ttl: float = 300.0,
    ):
        self.base_url = self._validate_base_url(base_url)
        self.session = session if session is not None else requests.Session()
        self.timeout = (connect_timeout, read_timeout)
        self.max_response_bytes = max_response_bytes
        self._capability_cache_ttl = capability_cache_ttl
        self._capability: str = CAP_UNKNOWN
        # Single shared timestamp for the capability cache. Both ``capabilities()`` and
        # ``capability_report()`` read/write the same ``_capability``/``_capability_at``
        # pair (via ``_remember_capability``) so that calling one and then the other
        # within the TTL never.
        self._capability_at: float = 0.0
        # Cached merged feature map + reachability from the last successful probe,
        # refreshed under the same TTL as the tier above. A real cache: a repeated
        # capability_report() (or capabilities()) within the TTL makes no network call.
        self._capability_features: Dict[str, bool] = {}
        self._capability_reachable: bool = False

    @staticmethod
    def _validate_base_url(base_url: str) -> str:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("base_url must be a non-empty URL")
        normalized = base_url.strip().rstrip("/")
        parts = urlsplit(normalized)
        if parts.scheme.lower() not in _ALLOWED_SCHEMES:
            raise ValueError(f"base_url has unsupported scheme {parts.scheme!r}")
        if not parts.netloc:
            raise ValueError("base_url must include a host")
        return normalized

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = self._url(path)
        kwargs.setdefault("timeout", self.timeout)
        try:
            response = self.session.request(method, url, **kwargs)
        except requests.exceptions.Timeout as exc:
            raise GhidraClientError(
                "Ghidra service timed out", code="timeout"
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            raise GhidraClientError(
                "Failed to connect to Ghidra service", code="connection"
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise GhidraClientError(
                "Ghidra service request failed", code="request_error"
            ) from exc
        return response

    def _check_size(self, response: requests.Response) -> None:
        """Reject responses that exceed the configured maximum size."""
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                if int(declared) > self.max_response_bytes:
                    raise GhidraClientError(
                        "Ghidra response too large",
                        status=response.status_code,
                        code="too_large",
                    )
            except (TypeError, ValueError):
                # Malformed header: fall through to the actual-size check.
                pass
        # response.content is already buffered by requests for a normal
        # (non-streaming) call; measure it to catch an understated header.
        if len(response.content) > self.max_response_bytes:
            raise GhidraClientError(
                "Ghidra response too large",
                status=response.status_code,
                code="too_large",
            )

    def _raise_for_status(self, response: requests.Response) -> None:
        if response.status_code >= 400:
            raise GhidraClientError(
                f"Ghidra service returned HTTP {response.status_code}",
                status=response.status_code,
                code="http_error",
            )

    def _parse_json(self, response: requests.Response) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise GhidraClientError(
                "Ghidra service returned invalid JSON",
                status=response.status_code,
                code="invalid_response",
            ) from exc

    def _json_request(self, method: str, path: str, **kwargs) -> Any:
        response = self._request(method, path, **kwargs)
        self._check_size(response)
        self._raise_for_status(response)
        return self._parse_json(response)

    # ------------------------------------------------------------------ #
    # Legacy-compatible endpoints
    # ------------------------------------------------------------------ #
    def analyze_b64(
        self, file_b64: str, filename: str, persist: bool = True
    ) -> Any:
        """Upload a base64-encoded binary and start analysis (legacy route)."""
        payload = {"file_b64": file_b64, "filename": filename, "persist": persist}
        return self._json_request("POST", "/analyze_b64", json=payload)

    def list_jobs(self) -> Any:
        return self._json_request("GET", "/jobs")

    def get_status(self, job_id: str) -> Any:
        return self._json_request("GET", f"/status/{job_id}")

    def call_tool(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Invoke a Ghidra tool endpoint."""
        try:
            response = self._request("POST", f"/tools/{endpoint}", json=payload)
            self._check_size(response)
            self._raise_for_status(response)
        except GhidraClientError as exc:
            return {"error": exc.message}
        try:
            return response.json()
        except ValueError:
            return {"result": response.text}

    def status(self, job_id: str) -> Dict[str, Any]:
        return self.call_tool("status", {"job_id": job_id})

    def list_functions(
        self, job_id: str, offset: Optional[int] = None, limit: Optional[int] = None
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"job_id": job_id}
        if offset is not None:
            payload["offset"] = offset
        if limit is not None:
            payload["limit"] = limit
        return self.call_tool("list_functions", payload)

    def decompile_function(self, job_id: str, addr: str) -> Dict[str, Any]:
        return self.call_tool("decompile_function", {"job_id": job_id, "addr": addr})

    def get_xrefs(self, job_id: str, addr: str) -> Dict[str, Any]:
        return self.call_tool("get_xrefs", {"job_id": job_id, "addr": addr})

    def list_imports(self, job_id: str) -> Dict[str, Any]:
        return self.call_tool("list_imports", {"job_id": job_id})

    def list_strings(
        self, job_id: str, min_length: Optional[int] = None
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"job_id": job_id}
        if min_length is not None:
            payload["min_length"] = min_length
        return self.call_tool("list_strings", payload)

    def query_artifacts(
        self, job_id: str, query: str, regex: bool = False
    ) -> Dict[str, Any]:
        return self.call_tool(
            "query_artifacts", {"job_id": job_id, "query": query, "regex": regex}
        )

    # ------------------------------------------------------------------ # Direct,
    # raising tool results for the Analysis workspace.
    def _tool_json(self, endpoint: str, payload: Dict[str, Any]) -> Any:
        return self._json_request("POST", f"/tools/{endpoint}", json=payload)

    # A private sentinel meaning "this v1 route is not implemented (404/405);
    # use the legacy fallback". It is distinct from a legitimate ``None`` body
    # and from an error (timeout/5xx/malformed), which still raise.
    _V1_ABSENT = object()

    def _v1_get(self, path: str, *, params: Optional[Dict[str, Any]] = None) -> Any:
        """GET a v1 route, returning parsed JSON, or ``_V1_ABSENT`` on 404/405."""
        response = self._request("GET", path, params=params)
        if response.status_code in (404, 405):
            return self._V1_ABSENT
        self._check_size(response)
        self._raise_for_status(response)
        return self._parse_json(response)

    def _prefers_v1(self) -> bool:
        return self.capabilities_safe() == CAP_V1

    def fetch_functions(
        self,
        job_id: str,
        offset: int = 0,
        limit: int = 100,
        query: Optional[str] = None,
    ) -> Any:
        """List functions, preferring the v1 results route (``items`` +"""
        q = query.strip() if isinstance(query, str) else None
        if self._prefers_v1():
            params: Dict[str, Any] = {"offset": offset, "limit": limit}
            if q:
                params["q"] = q
            doc = self._v1_get(
                f"/v1/results/{job_id}/functions",
                params=params,
            )
            if doc is not self._V1_ABSENT:
                out = self._normalize_functions(doc)
                out["search_supported"] = True
                return out
        legacy = self._tool_json(
            "list_functions",
            {"job_id": job_id, "offset": offset, "limit": limit},
        )
        if isinstance(legacy, dict):
            legacy = dict(legacy)
            # The legacy tool has no global name/address search. Advertise that
            # so the UI applies a local, current-page-only filter and labels the
            # limitation instead of implying the whole program was searched.
            legacy.setdefault("search_supported", False)
        return legacy

    @staticmethod
    def _normalize_functions(doc: Any) -> Dict[str, Any]:
        if not isinstance(doc, dict):
            return {"functions": [], "items": []}
        items = doc.get("items")
        if not isinstance(items, list):
            items = doc.get("functions") if isinstance(doc.get("functions"), list) else []
        out = dict(doc)
        # Provide both keys so every consumer sees the list regardless of which
        # name it reads. The v1 item schema (addr/name/size) is already tolerated
        # by the browser accessors; leave items untouched rather than lose fields.
        out["items"] = items
        out["functions"] = items
        out.setdefault("source", "v1")
        return out

    def fetch_decompile(self, job_id: str, addr: str) -> Any:
        """Fetch decompiled pseudocode, preferring the structured v1 route."""
        if self._prefers_v1():
            response = self._request(
                "GET", f"/v1/results/{job_id}/function/{addr}/decompile"
            )
            if response.status_code not in (404, 405):
                self._check_size(response)
                self._raise_for_status(response)
                try:
                    doc = response.json()
                except ValueError:
                    doc = {"result": response.text}
                return self._normalize_decompile(doc)
            # 404/405 -> route absent, fall through to the legacy tool.
        response = self._request(
            "POST",
            "/tools/decompile_function",
            json={"job_id": job_id, "addr": addr},
        )
        self._check_size(response)
        self._raise_for_status(response)
        try:
            return response.json()
        except ValueError:
            return {"result": response.text}

    @staticmethod
    def _normalize_decompile(doc: Any) -> Dict[str, Any]:
        if isinstance(doc, str):
            return {"content": doc, "result": doc, "content_type": "text/plain"}
        if not isinstance(doc, dict):
            return {"content": "", "result": ""}
        out = dict(doc)
        # Canonicalize the pseudocode text under both `content` (v1) and
        # `result` (legacy) so the browser's extractor finds it either way.
        text = (
            doc.get("content")
            or doc.get("result")
            or doc.get("decompilation")
            or doc.get("pseudocode")
            or doc.get("code")
            or doc.get("c")
            or ""
        )
        out.setdefault("content", text)
        out.setdefault("result", text)
        return out

    def fetch_xrefs(self, job_id: str, addr: str) -> Any:
        """Fetch cross-references, preferring the v1 results route."""
        if self._prefers_v1():
            doc = self._v1_get(f"/v1/results/{job_id}/xrefs/{addr}")
            if doc is not self._V1_ABSENT:
                return self._normalize_xrefs(doc)
        return self._tool_json("get_xrefs", {"job_id": job_id, "addr": addr})

    @staticmethod
    def _normalize_xrefs(doc: Any) -> Dict[str, Any]:
        if not isinstance(doc, dict):
            return {"callers": [], "callees": [], "xrefs": {"from": [], "to": []}}
        xrefs = doc.get("xrefs")
        if isinstance(xrefs, dict):
            raw_from = xrefs.get("from") if isinstance(xrefs.get("from"), list) else []
            raw_to = xrefs.get("to") if isinstance(xrefs.get("to"), list) else []
            callers = [_addr_of(x) for x in raw_from]
            callees = [_addr_of(x) for x in raw_to]
            out = dict(doc)
            out["callers"] = [c for c in callers if c]
            out["callees"] = [c for c in callees if c]
            return out
        return doc

    def fetch_imports(
        self, job_id: str, offset: int = 0, limit: int = 100
    ) -> Any:
        if self._prefers_v1():
            doc = self._v1_get(
                f"/v1/results/{job_id}/imports",
                params={"offset": offset, "limit": limit},
            )
            if doc is not self._V1_ABSENT:
                return self._normalize_list(doc, "imports")
        return self._tool_json("list_imports", {"job_id": job_id})

    def fetch_strings(
        self,
        job_id: str,
        min_length: Optional[int] = None,
        offset: int = 0,
        limit: int = 100,
    ) -> Any:
        if self._prefers_v1():
            params: Dict[str, Any] = {"offset": offset, "limit": limit}
            if min_length is not None:
                params["min_length"] = min_length
            doc = self._v1_get(
                f"/v1/results/{job_id}/strings", params=params
            )
            if doc is not self._V1_ABSENT:
                return self._normalize_list(doc, "strings")
        payload: Dict[str, Any] = {"job_id": job_id}
        if min_length is not None:
            payload["min_length"] = min_length
        return self._tool_json("list_strings", payload)

    @staticmethod
    def _normalize_list(doc: Any, key: str) -> Dict[str, Any]:
        if not isinstance(doc, dict):
            return {key: [], "items": []}
        items = doc.get(key)
        if not isinstance(items, list):
            items = doc.get("items") if isinstance(doc.get("items"), list) else []
        out = dict(doc)
        out[key] = items
        out["items"] = items
        return out

    def fetch_query(
        self,
        job_id: str,
        query: str,
        regex: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> Any:
        """Search artifacts, preferring ``POST /v1/query``."""
        if self._prefers_v1():
            body = {
                "job_id": job_id,
                "query": query,
                "regex": regex,
                "offset": offset,
                "limit": limit,
            }
            response = self._request("POST", "/v1/query", json=body)
            if response.status_code not in (404, 405):
                self._check_size(response)
                if response.status_code in (400, 422):
                    raise GhidraClientError(
                        "The search pattern is invalid or timed out.",
                        status=response.status_code,
                        code="invalid_query",
                    )
                self._raise_for_status(response)
                return self._normalize_query(self._parse_json(response))
        return self._tool_json(
            "query_artifacts",
            {"job_id": job_id, "query": query, "regex": regex},
        )

    @staticmethod
    def _normalize_query(doc: Any) -> Dict[str, Any]:
        if not isinstance(doc, dict):
            return {"matches": [], "results": [], "count": 0}
        matches = doc.get("matches")
        if not isinstance(matches, list):
            matches = doc.get("results") if isinstance(doc.get("results"), list) else []
        out = dict(doc)
        out["matches"] = matches
        out["results"] = matches
        return out

    def capabilities(self, *, force: bool = False) -> str:
        """Probe ``/v1/capabilities`` and return ``"v1"`` or ``"legacy"``."""
        now = time.monotonic()
        if (
            not force
            and self._capability != CAP_UNKNOWN
            and (now - self._capability_at) < self._capability_cache_ttl
        ):
            return self._capability

        response = self._request("GET", "/v1/capabilities")

        if response.status_code == 200:
            self._check_size(response)
            # Must be valid JSON to count as a real v1 endpoint.
            payload = self._parse_json(response)
            # Also cache the merged feature map + reachability under the same entry that
            # ``capability_report()`` reads, so a capabilities()-then-
            # capability_report() (or the reverse) within the TTL shares this one probe
            # instead of issuing a second.
            return self._remember_capability(
                CAP_V1, reachable=True, features=normalize_capabilities(payload)
            )
        if response.status_code in (404, 405):
            return self._remember_capability(CAP_LEGACY, reachable=True, features={})

        raise GhidraClientError(
            f"Capability probe returned HTTP {response.status_code}",
            status=response.status_code,
            code="capability_indeterminate",
        )

    def _remember_capability(
        self,
        value: str,
        *,
        reachable: bool = True,
        features: Optional[Dict[str, bool]] = None,
    ) -> str:
        # Update all capability-cache fields atomically so both public views agree.
        self._capability = value
        self._capability_at = time.monotonic()
        self._capability_reachable = reachable
        self._capability_features = dict(features) if features is not None else {}
        return value

    def capabilities_safe(self) -> str:
        """Like :meth:`capabilities` but never raises (returns ``unknown``)."""
        try:
            return self.capabilities()
        except GhidraClientError:
            return CAP_UNKNOWN

    # A v1 service advertises optional features in its /v1/capabilities body. Legacy
    # services expose none of them, but the web layer can *synthesize* a couple (a
    # program summary from status+functions, and a bounded call graph from xrefs)
    # without any v1 support.

    def _probe_capabilities(self) -> tuple:
        """One network probe. Returns ``(tier, reachable, features_map)``."""
        tier = CAP_UNKNOWN
        reachable = False
        features: Dict[str, bool] = {}
        try:
            response = self._request("GET", "/v1/capabilities")
            reachable = True
            if response.status_code == 200:
                try:
                    self._check_size(response)
                    payload = self._parse_json(response)
                    features = normalize_capabilities(payload)
                    tier = self._remember_capability(
                        CAP_V1, reachable=True, features=features
                    )
                except GhidraClientError:
                    tier = CAP_UNKNOWN  # reachable but malformed v1 body
            elif response.status_code in (404, 405):
                tier = self._remember_capability(
                    CAP_LEGACY, reachable=True, features={}
                )
            else:
                tier = CAP_UNKNOWN
        except GhidraClientError:
            reachable = False
            tier = CAP_UNKNOWN
        return tier, reachable, features

    def capability_report(self, *, force: bool = False) -> Dict[str, Any]:
        """Return a safe capability report without ever raising."""
        now = time.monotonic()
        # Shares the single ``_capability``/``_capability_at`` cache entry with
        # ``capabilities()`` (both written by ``_remember_capability``), so a cold
        # ``capabilities()`` call followed by ``capability_report()`` -- or the reverse
        # -- within the TTL costs exactly one.
        cache_valid = (
            not force
            and self._capability != CAP_UNKNOWN
            and (now - self._capability_at) < self._capability_cache_ttl
        )
        if cache_valid:
            tier = self._capability
            reachable = self._capability_reachable
            v1_features = dict(self._capability_features)
        else:
            # ``_probe_capabilities`` calls ``_remember_capability`` itself on a
            # definitive outcome, which already updates the shared tier, timestamp,
            # reachability, and feature-map cache -- no separate write needed here.
            tier, reachable, v1_features = self._probe_capabilities()

        def feature(key: str, *, synth: bool = False) -> Dict[str, Any]:
            if v1_features.get(key):
                return {"available": True, "source": "v1"}
            if synth and tier != CAP_UNKNOWN:
                # Synthesizable on any reachable service (v1 without the native
                # feature, or legacy). Not offered when the service is unknown.
                return {"available": True, "source": "synthesized"}
            return {"available": False, "source": "none"}

        features = {
            "summary": feature("summary", synth=True),
            "callgraph": feature("callgraph", synth=True),
            "types": feature("types"),
            "globals": feature("globals"),
            "annotations": feature("annotations"),
            "multipart_upload": feature("multipart_upload"),
            "hexdump": feature("hexdump"),
            "export": feature("export"),
            "cancellation": feature("cancellation"),
            "deduplication": feature("deduplication"),
            "string_references": feature("string_references"),
            # Attack Surface is native-v1 only (no synthesis): either the
            # ``capabilities.security_index`` or the ``features.attack_surface``
            # flag turns it on, gated independently from every other feature.
            "attack_surface": feature("attack_surface"),
        }
        return {"tier": tier, "reachable": reachable, "features": features}

    def feature_available(self, name: str, *, force: bool = False) -> bool:
        """True when the service natively advertises WebUI feature ``name``."""
        report = self.capability_report(force=force)
        feat = report.get("features", {}).get(name)
        return bool(feat and feat.get("available") and feat.get("source") == "v1")

    def fetch_summary(self, job_id: str) -> Dict[str, Any]:
        """Return a program summary."""
        if self.capabilities_safe() == CAP_V1:
            for path in (
                f"/v1/results/{job_id}/summary",
                f"/v1/jobs/{job_id}/summary",
            ):
                try:
                    doc = self._v1_get(path)
                except GhidraClientError:
                    continue  # transient/5xx on one route: try the other
                if doc is self._V1_ABSENT:
                    continue
                if isinstance(doc, dict):
                    return self._normalize_summary(doc)

        status: Any = {}
        try:
            status = self._tool_json("status", {"job_id": job_id})
        except GhidraClientError:
            status = {}
        function_count = None
        try:
            fns = self._tool_json(
                "list_functions", {"job_id": job_id, "offset": 0, "limit": 1}
            )
            if isinstance(fns, dict):
                for key in ("total", "count", "function_count"):
                    if isinstance(fns.get(key), int):
                        function_count = fns[key]
                        break
        except GhidraClientError:
            pass

        summary: Dict[str, Any] = {"source": "synthesized", "job_id": job_id}
        if isinstance(status, dict):
            for key in (
                "status",
                "filename",
                "program",
                "language",
                "compiler",
                "image_base",
                "sha256",
                "md5",
                "hash",
                "analysis_time",
                "elapsed",
                "warnings",
                "schema_version",
                "analyzer_version",
            ):
                if key in status:
                    summary[key] = status[key]
        if function_count is not None:
            summary["function_count"] = function_count
        return summary

    @staticmethod
    def _normalize_summary(doc: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(doc)
        out["source"] = "v1"
        counts = doc.get("counts")
        if isinstance(counts, dict):
            if isinstance(counts.get("functions"), int):
                out.setdefault("function_count", counts["functions"])
        if "program" not in out and isinstance(doc.get("program_name"), str):
            out["program"] = doc["program_name"]
        return out

    def fetch_callgraph(
        self,
        job_id: str,
        addr: str,
        *,
        depth: int = 2,
        max_nodes: int = 40,
        max_edges: int = 80,
        max_requests: int = 40,
    ) -> Dict[str, Any]:
        """Return a bounded call-graph neighborhood around ``addr``."""
        depth = max(0, min(int(depth), 4))
        max_nodes = max(1, min(int(max_nodes), 200))

        if self.feature_available("callgraph"):
            doc = self._v1_get(
                f"/v1/results/{job_id}/graph/{addr}",
                params={"depth": depth, "limit": max_nodes},
            )
            if doc is not self._V1_ABSENT and isinstance(doc, dict):
                return self._normalize_native_graph(doc, addr, depth)
        return self._synthesize_callgraph(
            job_id,
            addr,
            depth=depth,
            max_nodes=max_nodes,
            max_edges=max_edges,
            max_requests=max_requests,
        )

    @staticmethod
    def _normalize_native_graph(
        doc: Dict[str, Any], addr: str, depth: int
    ) -> Dict[str, Any]:
        raw_nodes = doc.get("nodes") if isinstance(doc.get("nodes"), list) else []
        node_addrs = []
        node_names: Dict[str, str] = {}
        for n in raw_nodes:
            if isinstance(n, dict):
                a = n.get("addr") or n.get("address")
                if isinstance(a, str) and a:
                    node_addrs.append(a)
                    if isinstance(n.get("name"), str):
                        node_names[a] = n["name"]
            elif isinstance(n, str) and n:
                node_addrs.append(n)
        raw_edges = doc.get("edges") if isinstance(doc.get("edges"), list) else []
        edges = []
        for e in raw_edges:
            if not isinstance(e, dict):
                continue
            src = e.get("source", e.get("from"))
            dst = e.get("target", e.get("to"))
            if isinstance(src, str) and isinstance(dst, str) and src and dst:
                edge = {"from": src, "to": dst}
                if isinstance(e.get("type"), str):
                    edge["type"] = e["type"]
                edges.append(edge)
        if addr not in node_addrs:
            node_addrs.insert(0, addr)
        return {
            "root": doc.get("root", addr),
            "nodes": node_addrs,
            "node_names": node_names,
            "edges": edges,
            "depth": doc.get("depth", depth),
            "truncated": bool(doc.get("truncated", False)),
            "source": "v1",
        }

    def _synthesize_callgraph(
        self,
        job_id: str,
        addr: str,
        *,
        depth: int = 2,
        max_nodes: int = 40,
        max_edges: int = 80,
        max_requests: int = 40,
    ) -> Dict[str, Any]:
        """Build a bounded call-graph neighborhood around ``addr`` from xrefs."""
        depth = max(0, min(int(depth), 4))
        max_nodes = max(1, min(int(max_nodes), 200))
        max_edges = max(1, min(int(max_edges), 400))
        max_requests = max(1, min(int(max_requests), 100))

        nodes: set = {addr}
        edges: list = []
        edge_seen: set = set()
        visited: set = set()
        queue = [(addr, depth)]  # (address, hops_remaining)
        requests_made = 0
        truncated = False

        while queue:
            current, hops = queue.pop(0)
            if hops <= 0 or current in visited:
                continue
            visited.add(current)
            if requests_made >= max_requests:
                truncated = True
                break
            requests_made += 1
            try:
                xref = self._tool_json(
                    "get_xrefs", {"job_id": job_id, "addr": current}
                )
            except GhidraClientError:
                continue
            callers = _addr_list(xref, "callers", "xrefs_to", "to")
            callees = _addr_list(xref, "callees", "xrefs_from", "from")
            stop = False
            for caller in callers:
                if not _add_edge(edges, edge_seen, caller, current, max_edges):
                    truncated = True
                    stop = True
                    break
                if _add_node(nodes, caller, max_nodes):
                    queue.append((caller, hops - 1))
                else:
                    truncated = True
            if stop:
                break
            for callee in callees:
                if not _add_edge(edges, edge_seen, current, callee, max_edges):
                    truncated = True
                    stop = True
                    break
                if _add_node(nodes, callee, max_nodes):
                    queue.append((callee, hops - 1))
                else:
                    truncated = True
            if stop:
                break

        return {
            "root": addr,
            "nodes": sorted(nodes),
            "edges": edges,
            "depth": depth,
            "truncated": truncated,
            "requests": requests_made,
            "source": "synthesized",
            "limits": {
                "max_nodes": max_nodes,
                "max_edges": max_edges,
                "max_requests": max_requests,
            },
        }

    def _require_v1_document(
        self, job_id: str, name: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        if self.capabilities_safe() != CAP_V1:
            raise GhidraClientError(
                f"The analysis service does not expose {name}; this requires "
                "the v1 Ghidra API.",
                code="capability_required",
            )
        paths = (
            f"/v1/results/{job_id}/{name}",
            f"/v1/jobs/{job_id}/{name}",
        )
        last_absent = False
        last_error: Optional[GhidraClientError] = None
        for i, path in enumerate(paths):
            try:
                doc = self._v1_get(path, params=params)
            except GhidraClientError as exc:
                last_error = exc
                continue
            if doc is self._V1_ABSENT:
                last_absent = True
                continue
            return self._normalize_list(doc, name) if isinstance(doc, dict) else doc
        if last_absent and last_error is None:
            raise GhidraClientError(
                f"The analysis service does not expose {name} on this build.",
                status=404,
                code="capability_required",
            )
        if last_error is not None:
            raise last_error
        return {name: [], "items": []}

    def fetch_types(
        self, job_id: str, offset: int = 0, limit: int = 100
    ) -> Dict[str, Any]:
        """Return types/structures/enums (native v1 only), paginated."""
        return self._require_v1_document(
            job_id, "types", {"offset": offset, "limit": limit}
        )

    def fetch_globals(
        self, job_id: str, offset: int = 0, limit: int = 100
    ) -> Dict[str, Any]:
        """Return global variables/data symbols (native v1 only), paginated."""
        return self._require_v1_document(
            job_id, "globals", {"offset": offset, "limit": limit}
        )

    # ------------------------------------------------------------------ # Sidecar
    # annotations (native v1 only; never fabricated locally). Annotations are overlays
    # stored by the Ghidra service alongside a job -- never edits to the exported
    # analysis artifacts.
    def fetch_annotations(
        self, job_id: str, addr: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return the annotation overlay plus its current ETag."""
        if self.capabilities_safe() != CAP_V1:
            raise GhidraClientError(
                "Annotations require the v1 Ghidra API.",
                code="capability_required",
            )
        params = {"addr": addr} if addr else None
        response = self._request(
            "GET", f"/v1/jobs/{job_id}/annotations", params=params
        )
        self._check_size(response)
        self._raise_for_status(response)
        body = self._parse_json(response)
        etag = response.headers.get("ETag")
        out: Dict[str, Any] = {"annotations": body}
        if etag is not None:
            out["etag"] = etag
        elif isinstance(body, dict) and body.get("revision") is not None:
            out["etag"] = f'"{body["revision"]}"'
        return out

    def put_annotation(
        self,
        job_id: str,
        addr: str,
        payload: Dict[str, Any],
        *,
        if_match: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create/update a sidecar annotation via the v1 service."""
        if self.capabilities_safe() != CAP_V1:
            raise GhidraClientError(
                "Annotations require the v1 Ghidra API.",
                code="capability_required",
            )
        headers = {"If-Match": if_match} if if_match else None

        body = dict(payload)
        body["job_id"] = job_id
        body["addr"] = addr
        if if_match and "revision" not in body:
            body["revision"] = if_match.strip('"')
        response = self._request(
            "PUT",
            f"/v1/jobs/{job_id}/annotations/{addr}",
            json=body,
            headers=headers,
        )
        if response.status_code not in (404, 405):
            return self._finish_annotation_write(response)

        # 2) Collection PATCH fallback (single-entry list).
        entry = {"entity_id": addr}
        for key in ("display_name", "comment", "tags", "confidence"):
            if key in payload:
                entry[key] = payload[key]
        response = self._request(
            "PATCH",
            f"/v1/jobs/{job_id}/annotations",
            json={"annotations": [entry]},
            headers=headers,
        )
        return self._finish_annotation_write(response)

    def _finish_annotation_write(self, response) -> Dict[str, Any]:
        self._check_size(response)
        if response.status_code == 409:
            raise GhidraClientError(
                "This annotation was changed by someone else; reload and retry.",
                status=409,
                code="conflict",
            )
        self._raise_for_status(response)
        body = self._parse_json(response)
        etag = response.headers.get("ETag")
        out: Dict[str, Any] = {"annotation": body}
        if etag is not None:
            out["etag"] = etag
        elif isinstance(body, dict) and body.get("revision") is not None:
            out["etag"] = f'"{body["revision"]}"'
        return out

    # ------------------------------------------------------------------ #
    # Upload (multipart preferred, base64 fallback).
    # ------------------------------------------------------------------ #
    def upload_binary(
        self, data: bytes, filename: str, *, persist: bool = True, force: bool = False
    ) -> Dict[str, Any]:
        """Upload a binary for analysis, preferring v1 multipart."""
        if self.feature_available("multipart_upload"):
            files = {"file": (filename, data)}
            params = {"persist": str(persist).lower(), "force": str(force).lower()}
            response = self._request(
                "POST", "/v1/jobs", files=files, params=params
            )
            if response.status_code not in (404, 405):
                self._check_size(response)
                self._raise_for_status(response)
                return self._normalize_upload(self._parse_json(response))
            # 404/405 only -> route genuinely absent, use legacy fallback.

        import base64

        encoded = base64.b64encode(data).decode("ascii")
        return self._normalize_upload(
            self.analyze_b64(encoded, filename, persist=persist)
        )

    @staticmethod
    def _normalize_upload(doc: Any) -> Dict[str, Any]:
        """Normalize an upload response to a stable browser shape."""
        if not isinstance(doc, dict):
            return {"status": "queued"}
        out = dict(doc)
        if "job_id" not in out and isinstance(out.get("reused_job_id"), str):
            out["job_id"] = out["reused_job_id"]
        out.setdefault("status", "queued")
        return out

    # ------------------------------------------------------------------ #
    # Job lifecycle (v1 list/get/cancel/delete, legacy list/status fallback).
    # ------------------------------------------------------------------ #
    def list_jobs_normalized(self) -> Dict[str, Any]:
        """Return a normalized, redacted job list."""
        doc = self._V1_ABSENT
        if self._prefers_v1():
            doc = self._v1_get("/v1/jobs")
        if doc is self._V1_ABSENT:
            doc = self._json_request("GET", "/jobs")
        items = []
        if isinstance(doc, dict):
            raw = doc.get("items")
            if not isinstance(raw, list):
                raw = doc.get("jobs") if isinstance(doc.get("jobs"), list) else []
            items = raw
        elif isinstance(doc, list):
            items = doc
        return {"items": [redact_job(j) for j in items if isinstance(j, dict)]}

    def get_job(self, job_id: str) -> Dict[str, Any]:
        """Return one job's redacted status."""
        doc = self._V1_ABSENT
        if self._prefers_v1():
            doc = self._v1_get(f"/v1/jobs/{job_id}")
        if doc is self._V1_ABSENT:
            doc = self._json_request("GET", f"/status/{job_id}")
        return redact_job(doc if isinstance(doc, dict) else {})

    def cancel_job(self, job_id: str) -> Dict[str, Any]:
        """Cancel a job via ``POST /v1/jobs/<id>/cancel`` (v1 only)."""
        if self.capabilities_safe() != CAP_V1:
            raise GhidraClientError(
                "Job cancellation requires the v1 Ghidra API.",
                code="capability_required",
            )
        response = self._request("POST", f"/v1/jobs/{job_id}/cancel")
        self._check_size(response)
        if response.status_code == 409:
            raise GhidraClientError(
                "The job already reached a terminal state.",
                status=409,
                code="conflict",
            )
        self._raise_for_status(response)
        try:
            return redact_job(response.json())
        except ValueError:
            return {"status": "cancelled"}

    def delete_job(self, job_id: str) -> Dict[str, Any]:
        """Delete a job via ``DELETE /v1/jobs/<id>`` (v1 only)."""
        if self.capabilities_safe() != CAP_V1:
            raise GhidraClientError(
                "Job deletion requires the v1 Ghidra API.",
                code="capability_required",
            )
        response = self._request("DELETE", f"/v1/jobs/{job_id}")
        self._check_size(response)
        self._raise_for_status(response)
        try:
            body = response.json()
        except ValueError:
            body = {}
        return {"deleted": True, "job_id": job_id, **(body if isinstance(body, dict) else {})}

    # ------------------------------------------------------------------ #
    # Hexdump / export (native v1 only; bounded).
    # ------------------------------------------------------------------ #
    def fetch_hexdump(
        self, job_id: str, start: str, length: int = 16
    ) -> Dict[str, Any]:
        """Return a bounded hex slice of analyzed program memory."""
        if self.capabilities_safe() != CAP_V1:
            raise GhidraClientError(
                "Hexdump requires the v1 Ghidra API.",
                code="capability_required",
            )
        length = max(1, min(int(length), 4096))
        response = self._request(
            "GET",
            f"/v1/results/{job_id}/hexdump/{start}",
            params={"length": length},
        )
        self._check_size(response)
        if response.status_code == 404:
            raise GhidraClientError(
                "The requested address was not exported for this program.",
                status=404,
                code="not_found",
            )
        if response.status_code in (400, 422):
            raise GhidraClientError(
                "The requested hexdump range is invalid or too large.",
                status=response.status_code,
                code="invalid_range",
            )
        self._raise_for_status(response)
        return self._parse_json(response)

    def export_archive(self, job_id: str):
        """Return ``(content_bytes, content_type, filename)`` for a job export."""
        if self.capabilities_safe() != CAP_V1:
            raise GhidraClientError(
                "Archive export requires the v1 Ghidra API.",
                code="capability_required",
            )
        response = self._request("GET", f"/v1/jobs/{job_id}/export")
        self._check_size(response)
        self._raise_for_status(response)
        content_type = response.headers.get("Content-Type", "application/zip")
        # Only ever advertise a zip; do not echo an unexpected upstream type.
        if "zip" not in content_type.lower():
            content_type = "application/zip"
        return response.content, content_type, f"{job_id}.zip"

    # ------------------------------------------------------------------ # Security
    # index / attack surface (native v1 only; deterministic evidence-based triage
    # priorities -- NOT vulnerability verdicts).
    def _require_security_v1(self) -> None:
        if self.capabilities_safe() != CAP_V1:
            raise GhidraClientError(
                "The attack-surface security index requires the v1 Ghidra API.",
                code="capability_required",
            )

    @staticmethod
    def _is_unavailable_envelope(doc: Any) -> bool:
        return isinstance(doc, dict) and doc.get("available") is False

    def fetch_security_summary(self, job_id: str) -> Dict[str, Any]:
        """Return the security-index summary document."""
        self._require_security_v1()
        response = self._request("GET", f"/v1/results/{job_id}/security/summary")
        self._check_size(response)
        # A genuinely absent route (older v1 build without the security index)
        # is surfaced as capability_required, not as a summary.
        if response.status_code in (404, 405):
            raise GhidraClientError(
                "This v1 build does not expose the attack-surface security index.",
                status=response.status_code,
                code="capability_required",
            )
        self._raise_for_status(response)
        doc = self._parse_json(response)
        if not isinstance(doc, dict):
            raise GhidraClientError(
                "The security summary response was malformed.",
                status=response.status_code,
                code="invalid_response",
            )
        return doc

    def fetch_security_functions(
        self,
        job_id: str,
        *,
        offset: int = 0,
        limit: int = 25,
        band: Optional[str] = None,
        category: Optional[str] = None,
        min_score: Optional[float] = None,
        q: Optional[str] = None,
        rank: Optional[int] = None,
        sort: str = "score",
        order: str = "desc",
    ) -> Dict[str, Any]:
        """Return one page of ranked security functions (``{items, pagination}``)."""
        self._require_security_v1()
        params: Dict[str, Any] = {"offset": offset, "limit": limit, "sort": sort, "order": order}
        if band:
            params["band"] = band
        if category:
            params["category"] = category
        if min_score is not None:
            params["min_score"] = min_score
        if q:
            params["q"] = q
        if rank is not None:
            params["rank"] = rank
        response = self._request(
            "GET", f"/v1/results/{job_id}/security/functions", params=params
        )
        self._check_size(response)
        if response.status_code in (404, 405):
            raise GhidraClientError(
                "This v1 build does not expose the attack-surface security index.",
                status=response.status_code,
                code="capability_required",
            )
        if response.status_code == 409:
            self._raise_index_unavailable(response)
        if response.status_code == 422:
            raise GhidraClientError(
                "The ranked-functions query parameters were rejected by the service.",
                status=422,
                code="invalid_query",
            )
        self._raise_for_status(response)
        doc = self._parse_json(response)
        return self._normalize_security_functions(doc)

    @staticmethod
    def _normalize_security_functions(doc: Any) -> Dict[str, Any]:
        if not isinstance(doc, dict):
            return {"items": [], "pagination": {"total": 0, "offset": 0, "limit": 0}}
        items = doc.get("items")
        if not isinstance(items, list):
            items = []
        pagination = doc.get("pagination")
        if not isinstance(pagination, dict):
            pagination = {"total": len(items), "offset": 0, "limit": len(items)}
        return {"items": items, "pagination": pagination}

    def fetch_security_function(self, job_id: str, addr: str) -> Dict[str, Any]:
        """Return the detailed security explanation for one function."""
        self._require_security_v1()
        response = self._request(
            "GET", f"/v1/results/{job_id}/security/functions/{addr}"
        )
        self._check_size(response)
        if response.status_code in (404, 405):
            raise GhidraClientError(
                "No security explanation exists for that address.",
                status=404,
                code="not_found",
            )
        if response.status_code == 409:
            self._raise_index_unavailable(response)
        self._raise_for_status(response)
        doc = self._parse_json(response)
        if not isinstance(doc, dict):
            raise GhidraClientError(
                "The security function response was malformed.",
                status=response.status_code,
                code="invalid_response",
            )
        return doc

    def rescore_security(self, job_id: str) -> Dict[str, Any]:
        """Enqueue a security-index rescore for a completed job (``POST rescore``)."""
        self._require_security_v1()
        response = self._request("POST", f"/v1/jobs/{job_id}/rescore")
        self._check_size(response)
        if response.status_code in (404, 405):
            raise GhidraClientError(
                "This v1 build does not support rescoring the security index.",
                status=response.status_code,
                code="capability_required",
            )
        if response.status_code == 409:
            raise GhidraClientError(
                "This job cannot be rescored: it must be completed with its "
                "analysis artifacts present.",
                status=409,
                code="conflict",
            )
        self._raise_for_status(response)
        try:
            doc = response.json()
        except ValueError:
            doc = {}
        out: Dict[str, Any] = {"status": "queued", "job_id": job_id}
        if isinstance(doc, dict):
            out.update(doc)
        return out

    def _raise_index_unavailable(self, response) -> None:
        """Raise a GhidraClientError for a 409 security-index envelope."""
        envelope: Dict[str, Any] = {}
        try:
            body = response.json()
            if isinstance(body, dict):
                envelope = body
        except ValueError:
            envelope = {}
        status_label = str(envelope.get("status") or "unavailable")
        exc = GhidraClientError(
            "The security index is not available; rescore the completed job.",
            status=409,
            code="index_unavailable",
        )
        exc.envelope = {
            "available": False,
            "status": status_label,
            "rescore_available": bool(envelope.get("rescore_available", True)),
        }
        raise exc
