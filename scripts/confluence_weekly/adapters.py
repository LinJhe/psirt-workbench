#!/usr/bin/env python3
"""Reusable read-only Confluence Server/DC and CISA catalog clients.

The share edition has no organization endpoint, automatic credential-file
fallback, or company snapshot adapter. The PSIRT collector injects a GET-only
transport with redirect refusal. Credentials are never persisted by this module.
"""
from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, timedelta
from pathlib import Path
from typing import Callable

DEFAULT_BASE_URL = "https://confluence.example.invalid"
DEFAULT_TOKEN_ENV = "CONFLUENCE_TOKEN"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ENV_FILES = ()
CREATE_OK = (200, 201)
CISA_KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")
DEFAULT_KEV_MIRROR = REPO_ROOT / "kev" / "known_exploited_vulnerabilities.json"


class ConfluenceError(RuntimeError):
    """Non-retryable Confluence API failure (auth, bad payload, exhausted retries)."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def resolve_env(name: str, env_files=None) -> str | None:
    """os.environ first, then each env file in order (KEY=VALUE, quotes stripped).
    Generic — used for both Confluence/Jira tokens and plain settings (e.g. URL)."""
    val = os.environ.get(name, "").strip()
    if val:
        return val
    for path in (DEFAULT_ENV_FILES if env_files is None else env_files):
        try:
            p = Path(path)
            if not p.is_file():
                continue
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() == name:
                    v = v.strip().strip('"').strip("'").strip()
                    if v:
                        return v
        except OSError:
            continue
    return None


def resolve_token(token_env: str = DEFAULT_TOKEN_ENV,
                  env_files=None) -> str | None:
    return resolve_env(token_env, env_files)


def make_urllib_transport(timeout: float = 45.0) -> Callable:
    """GET-only stdlib transport with system TLS trust and no redirects."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise PermissionError('RedirectRefused')
    opener = urllib.request.build_opener(NoRedirect())
    def transport(method: str, url: str, headers: dict, body: bytes | None):
        if method != 'GET' or body is not None:
            raise PermissionError('ReadOnlyGuard')
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None:
            raise ValueError('HTTPSRequired')
        req = urllib.request.Request(url, data=body, method=method,
                                     headers=dict(headers))
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    return transport


class ConfluenceRestClient:
    """Read-only Confluence Server REST client with injectable transport."""

    def __init__(self, base_url: str, token: str, *, transport: Callable | None = None,
                 timeout: float = 45.0, max_attempts: int = 5,
                 backoff_base: float = 0.5, backoff_cap: float = 8.0,
                 writes_enabled: bool = False, clock=time.sleep):
        self.base = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.token = token
        self.max_attempts = max_attempts
        self.backoff_base = backoff_base
        self.backoff_cap = backoff_cap
        self.writes_enabled = writes_enabled
        self.clock = clock
        self.transport = transport or make_urllib_transport(timeout)

    # -- plumbing ----------------------------------------------------------
    def _guard_write(self, what: str) -> None:
        raise PermissionError('ReadOnlyGuard')

    def _sleep_backoff(self, attempt: int) -> None:
        d = min(self.backoff_cap, self.backoff_base * (2 ** attempt))
        d += random.uniform(0, 0.3)
        self.clock(d)

    def request(self, method: str, path: str, *, params: dict | None = None,
                body=None, write: bool = False):
        """Returns (status, parsed-json-or-None). Retries 429/5xx and transport
        failures with exponential backoff; raises ConfluenceError when exhausted."""
        if write or method != 'GET' or body is not None:
            self._guard_write(path)
        url = self.base + path
        if params:
            url = url + "?" + urllib.parse.urlencode(params)
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Authorization": f"Bearer {self.token}",
                   "Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        last_err = "n/a"
        for attempt in range(self.max_attempts):
            try:
                status, raw = self.transport(method, url, headers, payload)
            except ConfluenceError:
                raise
            except Exception as e:  # noqa: BLE001 — transport failure (DNS/TLS)
                last_err = f"{type(e).__name__}: {e}"
                if attempt == self.max_attempts - 1:
                    break
                self._sleep_backoff(attempt)
                continue
            if status == 429 or status >= 500:
                last_err = f"HTTP {status}"
                if attempt == self.max_attempts - 1:
                    break
                self._sleep_backoff(attempt)
                continue
            data = None
            if raw:
                try:
                    data = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    data = None
            return status, data
        raise ConfluenceError(
            f"{method} {path}: {last_err} after {self.max_attempts} attempts",
            status=None)

    # -- reads ---------------------------------------------------------------
    def get_page(self, page_id: str,
                 expand=("body.storage", "version", "title")) -> dict | None:
        status, data = self.request("GET", f"/rest/api/content/{page_id}",
                                    params={"expand": ",".join(expand)})
        if status == 404:
            return None
        if status != 200:
            raise ConfluenceError(f"Confluence API {status}: GET page {page_id} failed",
                                  status=status)
        return data

    def find_page_by_title(self, space_key: str, title: str,
                           expand=("version", "ancestors")) -> dict | None:
        status, data = self.request("GET", "/rest/api/content",
                                    params={"spaceKey": space_key, "title": title,
                                            "expand": ",".join(expand)})
        if status != 200:
            raise ConfluenceError(
                f"Confluence API {status}: title search in {space_key} failed",
                status=status)
        results = (data or {}).get("results") or []
        return results[0] if results else None

    def list_children(self, page_id: str, limit: int = 50) -> list[dict]:
        status, data = self.request("GET", f"/rest/api/content/{page_id}/child/page",
                                    params={"limit": limit})
        if status != 200:
            raise ConfluenceError(
                f"Confluence API {status}: children of {page_id} failed", status=status)
        return (data or {}).get("results") or []

class KevCatalogFileSource:
    """讀 kev/known_exploited_vulnerabilities.json（CISA KEV 鏡像）。"""

    def __init__(self, path):
        self.path = Path(path)

    def load(self) -> dict:
        if not self.path.is_file():
            raise FileNotFoundError(f"kev catalog not found: {self.path}")
        with open(self.path, encoding="utf-8") as f:
            raw = json.load(f)
        vulns = raw.get("vulnerabilities") or []
        catalog_date = max((str(v.get("dateAdded") or "")[:10] for v in vulns),
                           default="")
        return {"vulnerabilities": vulns, "catalog_date": catalog_date}


class KevLiveSource:
    """Live CISA catalog reader. PSIRT calls load_raw(), which never uses a mirror.

    Legacy load() explicitly labels its optional local fallback as mirror.
    """

    def __init__(self, *, url: str = CISA_KEV_URL, mirror_path=DEFAULT_KEV_MIRROR,
                 transport: Callable | None = None, timeout: float = 30.0):
        self.url = url
        self.mirror = KevCatalogFileSource(mirror_path)
        self.transport = transport or make_urllib_transport(timeout)

    def load_raw(self) -> dict:
        """Read the complete live catalog; propagate failures, never use a mirror."""
        status, raw = self.transport("GET", self.url,
                                     {"Accept": "application/json"}, None)
        if status != 200:
            raise RuntimeError(f"CISA_HTTP_{status}")
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("CISA catalog must be an object")
        return data

    def load(self) -> dict:
        try:
            data = self.load_raw()
            vulns = data.get("vulnerabilities") or []
            if vulns:
                return {
                    "vulnerabilities": vulns,
                    "catalog_date": max(
                        (str(v.get("dateAdded") or "")[:10] for v in vulns),
                        default=""),
                    "source": "live",
                }
        except Exception:  # noqa: BLE001 — 任何網路/解析失敗都走 fallback
            pass
        d = self.mirror.load()
        d["source"] = "mirror"
        return d


