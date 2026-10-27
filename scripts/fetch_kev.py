#!/usr/bin/env python3
"""Fetch CISA KEV and diff immutable local snapshots. No credentials or integrations.

Run: python3 scripts/fetch_kev.py
Fresh = fetched successfully this run; an old release date alone is not stale.
Failed runs retain the previous snapshot and show its data as stale, never zero.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from confluence_weekly.adapters import CISA_KEV_URL, KevLiveSource
else:
    from .confluence_weekly.adapters import CISA_KEV_URL, KevLiveSource

ROOT = Path(__file__).resolve().parent.parent


def index_catalog(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("vulnerabilities"), list):
        raise ValueError("InvalidCatalog")
    rows = raw["vulnerabilities"]
    if not rows:
        raise ValueError("EmptyCatalog")
    if type(raw.get("count")) is not int or raw["count"] != len(rows):
        raise ValueError("CatalogCountMismatch")
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("InvalidVulnerability")
        cve = row.get("cveID")
        if not isinstance(cve, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            raise ValueError("InvalidCVE")
        if cve in result:
            raise ValueError("DuplicateCVE")
        result[cve] = row
    return result


def diff_catalogs(previous, current):
    old, new = index_catalog(previous), index_catalog(current)
    added = [new[cve] for cve in sorted(new.keys() - old.keys())]
    removed = [old[cve] for cve in sorted(old.keys() - new.keys())]
    changed = []
    for cve in sorted(old.keys() & new.keys()):
        fields = {}
        # Compare every source field, including new/removed fields, not just dateAdded.
        for field in sorted(old[cve].keys() | new[cve].keys()):
            before_present, after_present = field in old[cve], field in new[cve]
            before, after = old[cve].get(field), new[cve].get(field)
            if before_present != after_present or before != after:
                fields[field] = {"before": before, "after": after,
                                 "before_present": before_present,
                                 "after_present": after_present}
        if fields:
            changed.append({"cveID": cve, "fields": fields})
    return {"added": added, "changed": changed, "removed": removed}


def atomic_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".kev-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def json_text(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def md_value(value):
    return json.dumps(value, ensure_ascii=False).replace("`", "\\`").replace("\n", " ")


def render_markdown(report):
    lines = ["# Daily KEV Update", "",
             f"Status: {report['status']}",
             f"Fetch Time (UTC): {report['fetch_timestamp']}",
             f"Source: {report['source']}",
             f"Catalog Version: {report.get('catalog_version') or 'Unknown'}",
             f"Source Update: {report.get('source_update_time') or 'Unknown'}",
             f"Total KEV: {report['total_vulnerability_count'] if report['total_vulnerability_count'] is not None else 'Unknown (fetch failed)'}",
             f"Previous Snapshot: {report.get('previous_snapshot') or 'None'}",
             f"Current Snapshot: {report.get('current_snapshot') or 'None'}", ""]
    for key, title in (("added", "Added"), ("changed", "Changed"), ("removed", "Removed")):
        lines.extend([f"## {title}", ""])
        rows = report[key]
        if rows is None:
            lines.append("- Not evaluated: fetch/validation failed; no zero-count claim.")
        elif report["status"] == "BASELINE_CREATED":
            lines.append("- Baseline created; no previous successful snapshot to compare.")
        elif not rows:
            lines.append("- None (0).")
        else:
            for row in rows:
                if key == "changed":
                    lines.append(f"- **{row['cveID']}**")
                    for field, change in row["fields"].items():
                        before = md_value(change["before"]) if change["before_present"] else "(field absent)"
                        after = md_value(change["after"]) if change["after_present"] else "(field absent)"
                        lines.append(f"  - {field}: {before} → {after}")
                else:
                    lines.append(f"- **{row['cveID']}** — {md_value(row.get('vendorProject'))} / {md_value(row.get('product'))}; dateAdded: {row.get('dateAdded', 'Unknown')}")
                    if row.get("shortDescription"):
                        lines.append(f"  - {md_value(row['shortDescription'])}")
        lines.append("")
    lines.extend(["## Data Health", "", f"- {report['data_health']}",
                  "- Fresh describes this fetch, not the age of the source release.",
                  "- No product affected / not affected determination is performed."])
    if report.get("error_category"):
        lines.append(f"- Error category: {report['error_category']}")
    if report.get("last_success"):
        last = report["last_success"]
        lines.append(f"- Last success (stale reference only): {last['fetch_timestamp']}; total {last['total_vulnerability_count']}; source update {last.get('source_update_time') or 'Unknown'}")
    return "\n".join(lines) + "\n"


def run(root=ROOT, collector=None):
    snapshot_dir, output_dir = root / "snapshots/kev", root / "outputs/kev"
    output_dir.mkdir(parents=True, exist_ok=True)
    # A directory lock serializes local executions without an extra lock file.
    lock = os.open(output_dir, os.O_RDONLY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _run(root, snapshot_dir, output_dir, collector)
    finally:
        os.close(lock)


def _run(root, snapshot_dir, output_dir, collector):
    timestamp = datetime.now(timezone.utc)
    report = {"source": CISA_KEV_URL, "fetch_timestamp": timestamp.isoformat(),
              "status": "FAILED", "data_health": "failed", "catalog_version": None,
              "source_update_time": None, "total_vulnerability_count": None,
              "previous_snapshot": None, "current_snapshot": None,
              "added": None, "changed": None, "removed": None, "counts": None}
    previous = None
    try:
        snapshots = sorted(snapshot_dir.glob("*.json"))
        if snapshots:
            path = snapshots[-1]
            report["previous_snapshot"] = str(path.relative_to(root))
            previous = json.loads(path.read_text(encoding="utf-8"))
            if previous.get("source") != CISA_KEV_URL:
                raise ValueError("PreviousSnapshotSourceMismatch")
            index_catalog(previous["raw_catalog"])
            for key in ("fetch_timestamp", "total_vulnerability_count"):
                if key not in previous:
                    raise ValueError("InvalidPreviousSnapshot")
        raw = (collector or KevLiveSource()).load_raw()
        index_catalog(raw)
        metadata = {"source": CISA_KEV_URL, "fetch_timestamp": timestamp.isoformat(),
                    "catalog_version": raw.get("catalogVersion"),
                    "source_update_time": raw.get("dateReleased"),
                    "total_vulnerability_count": len(raw["vulnerabilities"])}
        snapshot = {**metadata, "raw_catalog": raw}
        changes = diff_catalogs(previous["raw_catalog"], raw) if previous else {
            "added": [], "changed": [], "removed": []}
        report.update(metadata)
        report.update(changes)
        report["status"] = "SUCCESS" if previous else "BASELINE_CREATED"
        report["data_health"] = "fresh" if previous else "baseline"
        report["counts"] = {k: len(v) for k, v in changes.items()}
        filename = timestamp.strftime("%Y%m%dT%H%M%S.%fZ") + ".json"
        path = snapshot_dir / filename
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        # Exclusive creation: no previous success can be overwritten.
        with path.open("x", encoding="utf-8") as stream:
            try:
                stream.write(json_text(snapshot))
                stream.flush()
                os.fsync(stream.fileno())
            except BaseException:
                path.unlink(missing_ok=True)
                raise
        report["current_snapshot"] = str(path.relative_to(root))
    except Exception as exc:
        # Never print raw exception text, request bodies, or environment values.
        category = type(exc).__name__
        if isinstance(exc, RuntimeError) and re.fullmatch(r"CISA_HTTP_\d{3}", str(exc)):
            category = str(exc)
        report.update(status="FAILED", data_health="failed", error_category=category,
                      total_vulnerability_count=None, current_snapshot=None,
                      added=None, changed=None, removed=None, counts=None)
        if previous:
            report["last_success"] = {k: previous.get(k) for k in (
                "fetch_timestamp", "source_update_time", "total_vulnerability_count")}
            report["data_health"] = "failed (previous successful data is stale)"
    atomic_write(output_dir / "latest_diff.json", json_text(report))
    atomic_write(output_dir / "latest_diff.md", render_markdown(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        report = run()
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps({k: report.get(k) for k in (
        "status", "data_health", "total_vulnerability_count", "counts",
        "current_snapshot", "error_category")}, ensure_ascii=False))
    return 1 if report["status"] == "FAILED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
