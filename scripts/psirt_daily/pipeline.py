"""Fixture contract, immutable observations, compatible baselines and Daily output.

Only state.json is replaceable. A single atomic state commit occurs after all
run artifacts are durable. An interrupted run remains uncommitted evidence and
cannot become a comparison baseline. Local flock serializes reruns.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from zoneinfo import ZoneInfo

from .offline import install_offline_guard

SOURCES = ("kev", "salesforce", "dt", "jira")
STATUSES = {"SUCCESS", "PARTIAL", "FAILED", "NOT_CONFIGURED"}
SCHEMA = "psirt-daily-gate1/1"
RULE = "observation-diff/1"
MARKER = "PSIRT GATE 1 SYNTHETIC OUTPUT ONLY\n"
UNITS = {"kev": "CVE", "salesforce": "Case", "dt": "Finding", "jira": "Issue"}


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("TimestampRequired")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.utcoffset() is None:
        raise ValueError("TimezoneRequired")
    return result


def read_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("DuplicateJSONKey")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("NonFiniteJSON")

    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def write_new(path, data):
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def no_symlinks(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("SymlinkOutputRejected")


def prepare_root(path):
    root = Path(os.path.abspath(path))
    no_symlinks(root)
    root.mkdir(parents=True, exist_ok=True)
    marker = root / ".psirt-gate1"
    if not marker.exists():
        if any(root.iterdir()):
            raise ValueError("OutputMustBeEmptyOrGate1Managed")
        write_new(marker, MARKER.encode())
    no_symlinks(marker)
    if marker.read_text() != MARKER:
        raise ValueError("InvalidOutputMarker")
    for child in root.iterdir():
        no_symlinks(child)
    return root


def raw_index(name, raw):
    if name == "kev":
        # Import only after the offline guard is active; never invoke run()/collector.
        from fetch_kev import index_catalog
        return index_catalog(raw)
    if not isinstance(raw, list):
        raise ValueError("RecordsMustBeList")
    result = {}
    for row in raw:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
            raise ValueError("StableRecordIDRequired")
        if row["id"] in result:
            raise ValueError("DuplicateRecordID")
        result[row["id"]] = row
    return result


def diff(name, before, after):
    if name == "kev":
        from fetch_kev import diff_catalogs
        return diff_catalogs(before, after)
    old, new = raw_index(name, before), raw_index(name, after)
    changed = []
    for key in sorted(old.keys() & new.keys()):
        fields = {}
        for field in sorted(old[key].keys() | new[key].keys()):
            a, b = old[key].get(field), new[key].get(field)
            ap, bp = field in old[key], field in new[key]
            if ap != bp or a != b:
                fields[field] = {"before": a, "after": b,
                                 "before_present": ap, "after_present": bp}
        if fields:
            changed.append({"id": key, "fields": fields})
    return {"added": [new[k] for k in sorted(new.keys() - old.keys())],
            "changed": changed,
            "removed": [old[k] for k in sorted(old.keys() - new.keys())]}


def validate_source(name, item):
    if not isinstance(item, dict) or item.get("synthetic") is not True:
        raise ValueError("SyntheticSourceRequired")
    if item.get("status") not in STATUSES:
        raise ValueError("UnknownSourceStatus")
    if item["status"] == "NOT_CONFIGURED":
        if item.get("raw") is not None:
            raise ValueError("UnconfiguredSourceHasData")
        return None
    if not isinstance(item.get("scope"), dict) or not item["scope"]:
        raise ValueError("ExplicitScopeRequired")
    for key in ("source_version", "schema_version", "rule_version"):
        if not isinstance(item.get(key), str) or not item[key].strip():
            raise ValueError("VersionRequired")
    timestamp(item["observed_at"])
    if item.get("source_updated_at") is not None:
        timestamp(item["source_updated_at"])
    completeness = item["completeness"]
    if not isinstance(completeness, dict) or type(completeness.get("complete")) is not bool:
        raise ValueError("CompletenessRequired")
    if item["status"] == "FAILED":
        if completeness["complete"] or item.get("raw") is not None:
            raise ValueError("FailedSourceHasData")
        return None
    records = raw_index(name, item["raw"])
    expected = completeness.get("expected_count")
    if expected is not None and (type(expected) is not int or expected < len(records)):
        raise ValueError("InvalidExpectedCount")
    # Count mismatch and incomplete pages downgrade SUCCESS to PARTIAL.
    return records


def compatibility(item):
    return {k: item[k] for k in ("scope", "source_version", "schema_version", "rule_version")}


def load_baselines(root):
    path = root / "state.json"
    if not path.exists():
        # Do not silently reset a lost state file in an established output directory.
        if (root / "runs").exists() and any((root / "runs").iterdir()):
            raise ValueError("StateMissingRecoverToNewDirectory")
        return {}, {}
    state = read_json(path.read_bytes())
    if state.get("schema_version") != SCHEMA or state.get("synthetic") is not True:
        raise ValueError("InvalidState")
    refs = state["baselines"]
    if not isinstance(refs, dict) or set(refs) - set(SOURCES):
        raise ValueError("InvalidBaselines")
    loaded = {}
    for name, ref in refs.items():
        relative = Path(ref["path"])
        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 3:
            raise ValueError("InvalidBaselinePath")
        if relative.parts[0] != "runs" or relative.name != f"{name}.json":
            raise ValueError("InvalidBaselinePath")
        target = root / relative
        no_symlinks(target)
        data = target.read_bytes()
        if sha(data) != ref["sha256"]:
            raise ValueError("BaselineHashMismatch")
        snapshot = read_json(data)
        if (snapshot["source"] != name or snapshot["status"] != "SUCCESS"
                or snapshot["synthetic"] is not True
                or not snapshot["completeness"]["complete"]):
            raise ValueError("InvalidBaseline")
        validate_source(name, snapshot["observation"])
        loaded[name] = snapshot
    return refs, loaded


def observe(name, item, previous, previous_ref, now):
    result = {"source": name, "synthetic": True, "mode": "fixture",
              "status": "NOT_CONFIGURED", "last_successful_at": None,
              "observed_at": None, "source_updated_at": None, "scope": None,
              "source_version": None, "schema_version": None, "rule_version": None,
              "pipeline_rule_version": RULE, "scope_sha256": None,
              "completeness": {"complete": False, "expected_count": None},
              "fetched_count": None, "count_unit": UNITS[name],
              "baseline_ref": previous_ref, "baseline_created": False,
              "comparison": "not_configured", "changes": None, "counts": None,
              "snapshot_ref": None, "error_category": None,
              "previous_successful_at": previous["last_successful_at"] if previous else None}
    result["last_successful_at"] = result["previous_successful_at"]
    if item is None:
        return result
    try:
        records = validate_source(name, item)
        result.update({key: item.get(key) for key in (
            "status", "observed_at", "source_updated_at", "scope", "source_version",
            "schema_version", "rule_version")})
        result["completeness"] = copy.deepcopy(item.get("completeness", result["completeness"]))
        result["scope_sha256"] = sha(encoded(item["scope"])) if item.get("scope") else None
        if item["status"] == "NOT_CONFIGURED":
            return result
        if item["status"] == "FAILED":
            result.update(comparison="source_failed", error_category="SimulatedSourceFailure")
            return result
        result["fetched_count"] = len(records)
        complete = (item["status"] == "SUCCESS" and item["completeness"]["complete"]
                    and item["completeness"].get("expected_count", len(records)) == len(records))
        # An unknown total is acceptable only with explicit complete traversal evidence.
        if item["completeness"].get("expected_count") is None:
            complete = item["status"] == "SUCCESS" and item["completeness"]["complete"]
        if item["completeness"].get("pagination_exhausted", True) is not True:
            complete = False
        if not complete:
            result.update(status="PARTIAL", comparison="incomplete")
            result["completeness"]["complete"] = False
            return result
        old = previous["observation"] if previous else None
        differing = [k for k in compatibility(item) if old and item[k] != old[k]]
        if previous and previous["pipeline_rule_version"] != RULE:
            differing.append("pipeline_rule_version")
        if old and not differing and timestamp(item["observed_at"]) < timestamp(old["observed_at"]):
            raise ValueError("ObservationOutOfOrder")
        if old and not differing:
            result["changes"] = diff(name, old["raw"], item["raw"])
            result["counts"] = {k: len(v) for k, v in result["changes"].items()}
            result["comparison"] = "changed" if any(result["counts"].values()) else "unchanged"
        else:
            result["baseline_created"] = True
            result["comparison"] = "incompatible_baseline" if old else "baseline_created"
            result["incompatible_fields"] = differing
        result["last_successful_at"] = now
    except (ValueError, KeyError, TypeError) as exc:
        result.update(status="FAILED", comparison="validation_failed", fetched_count=None,
                      counts=None, changes=None, baseline_created=False,
                      error_category=type(exc).__name__)
        result["completeness"] = {"complete": False, "expected_count": None}
    return result


def followups(items, sources, observations):
    result = []
    if not isinstance(items, list):
        raise ValueError("FollowupsMustBeList")
    seen = set()
    for item in items:
        if not isinstance(item, dict) or item.get("synthetic") is not True:
            raise ValueError("SyntheticFollowupRequired")
        if not isinstance(item.get("id"), str) or not item["id"] or item["id"] in seen:
            raise ValueError("InvalidFollowupID")
        seen.add(item["id"])
        source, record_id = item["source"], item["record_id"]
        if source not in SOURCES:
            raise ValueError("InvalidFollowupSource")
        for key in ("owner", "action", "checkpoint", "blocker", "dates"):
            if key not in item:
                raise ValueError("FollowupFieldMissing")
        dates = item["dates"]
        if not isinstance(dates, dict) or set(dates) != {"reply", "remediation", "verification", "release"}:
            raise ValueError("SeparateDateTypesRequired")
        for value in [item["checkpoint"], *dates.values()]:
            if value is not None:
                timestamp(value)
        row = {key: copy.deepcopy(item[key]) for key in (
            "id", "source", "record_id", "owner", "action", "checkpoint", "blocker", "dates")}
        evidence = None
        observation = observations.get(source)
        if sources[source]["status"] in {"SUCCESS", "PARTIAL"} and observation:
            indexed = raw_index(source, observation["raw"])
            if record_id not in indexed:
                raise ValueError("FollowupRecordNotFound")
            rows = observation["raw"]["vulnerabilities"] if source == "kev" else observation["raw"]
            position = rows.index(indexed[record_id])
            suffix = f"/vulnerabilities/{position}" if source == "kev" else f"/{position}"
            evidence = {**sources[source]["snapshot_ref"],
                        "json_pointer": "/observation/raw" + suffix}
        row.update(synthetic=True, review_required=True, review_status="NOT_REVIEWED",
                   provenance="synthetic_followup_proposal", evidence_ref=evidence,
                   source_status=sources[source]["status"],
                   evidence_status="OBSERVED" if evidence else "UNAVAILABLE")
        result.append(row)
    return result


def display(value):
    # Source text is data; escape table syntax/HTML and keep each cell on one line.
    text = "Unknown / 待確認" if value is None else str(value)
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("`", "\\`"))


def render(report):
    lines = ["# PSIRT Daily — SYNTHETIC / NOT FOR PRODUCTION", "",
             f"Run: {report['run_id']}", f"Status: {report['status']}",
             f"UTC: {report['completed_at_utc']}", f"Asia/Taipei: {report['completed_at_local']}",
             "", "全部資料均為合成測試；SUCCESS 僅表示 fixture 完整有效，非公司 live 查詢成功。",
             "來源觀測與人工覆核分離；移除、RESOLVED、Exploitable 均不代表已修復或正式受影響。",
             "", "## 來源健康與變化", ""]
    for name, source in report["sources"].items():
        lines += [f"### {name} — {source['status']} (synthetic)", "",
                  f"- 最後成功處理時間 UTC：{display(source['last_successful_at'])}",
                  f"- Fixture 觀測時間：{display(source['observed_at'])}",
                  f"- 來源更新時間：{display(source['source_updated_at'])}",
                  f"- 範圍：{display(source['scope'])}",
                  f"- 版本／規則：{display(source['source_version'])} / {display(source['rule_version'])}",
                  f"- 完整性：{display(source['completeness'])}",
                  f"- 觀測筆數（{source['count_unit']}）：{display(source['fetched_count'])}",
                  f"- 比較結果：{source['comparison']}",
                  f"- 前次完整基準：{display(source['baseline_ref'])}",
                  f"- 本次證據：{display(source['snapshot_ref'])}"]
        if source["counts"] is None:
            lines.append("- 差異未計算：首次基準、未配置、失敗、不完整或不相容；不可解讀為零異動。")
        else:
            lines.append(f"- 異動筆數：{display(source['counts'])}；只代表同範圍來源觀測。")
            for kind, rows in source["changes"].items():
                for row in rows:
                    lines.append(f"- {kind}: {display(json.dumps(row, ensure_ascii=False))}")
        if source.get("incompatible_fields"):
            lines.append(f"- 不相容欄位：{display(source['incompatible_fields'])}；建立新基準，不計改善。")
        if source["error_category"]:
            lines.append(f"- 錯誤類別：{source['error_category']}；需檢查 fixture／來源契約。")
        lines.append("")
    lines += ["## 待跟進草稿 — synthetic / NOT_REVIEWED", "",
              "| ID | Owner（示例） | Action | Checkpoint | Blocker | Evidence |",
              "|---|---|---|---|---|---|"]
    for item in report["followups"]:
        lines.append("| " + " | ".join(display(item[key]) for key in (
            "id", "owner", "action", "checkpoint", "blocker", "evidence_ref")) + " |")
    for item in report["followups"]:
        lines.append("")
        lines.append(f"{display(item['id'])} 日期（全部為示例、未承諾）：" + "; ".join(
            f"{kind}={display(value)}" for kind, value in item["dates"].items()))
        lines.append("")
    if not report["followups"]:
        lines.append("未提供合成待辦；不代表正式案件沒有待辦。")
    lines += ["", "## 證據與人工覆核", "",
              f"- Fixture SHA256：{report['fixture_sha256']}（本 run 的 input.json）",
              "- 本 run 的 daily.json 保存完整 changes、source_run 與 evidence refs。",
              "- 未讀取或更新任何人工覆核紀錄；待辦是獨立草稿，未授權正式判定。",
              "- 未配置／失敗／partial 來源需補資料後重跑；歷史成功只供歷史參考。"]
    return "\n".join(lines) + "\n"


def run(fixture, output_dir):
    install_offline_guard()
    started = datetime.now(timezone.utc).isoformat()
    fixture_path = Path(fixture).resolve(strict=True)
    data = fixture_path.read_bytes()
    payload = read_json(data)
    if (not isinstance(payload, dict) or payload.get("synthetic") is not True
            or payload.get("schema_version") != SCHEMA):
        raise ValueError("SyntheticFixtureContractRequired")
    observations = payload.get("sources")
    if not isinstance(observations, dict) or set(observations) - set(SOURCES):
        raise ValueError("InvalidSourceNames")
    for item in observations.values():
        if (not isinstance(item, dict) or item.get("synthetic") is not True
                or item.get("mode", "fixture") != "fixture"):
            raise ValueError("SyntheticSourceRequired")
    root = prepare_root(output_dir)
    if fixture_path.is_relative_to(root):
        raise ValueError("InputOutputOverlap")
    lock = os.open(root, os.O_RDONLY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        refs, previous = load_baselines(root)
        next_refs = copy.deepcopy(refs)
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ-") + uuid4().hex[:12]
        run_dir = root / "runs" / run_id
        no_symlinks(run_dir)
        run_dir.mkdir(parents=True, exist_ok=False)
        write_new(run_dir / "input.json", data)
        sources = {}
        for name in SOURCES:
            item = observations.get(name)
            now = datetime.now(timezone.utc).isoformat()
            source = observe(name, item, previous.get(name), refs.get(name), now)
            source.update(run_id=run_id, processed_at_utc=now)
            snapshot = {**source, "observation": item}
            snapshot_data = encoded(snapshot)
            target = run_dir / f"{name}.json"
            write_new(target, snapshot_data)
            ref = {"path": target.relative_to(root).as_posix(), "sha256": sha(snapshot_data)}
            source["snapshot_ref"] = ref
            sources[name] = source
            if source["status"] == "SUCCESS":
                next_refs[name] = ref
        queue = followups(payload.get("followups", []), sources, observations)
        active = [s["status"] for s in sources.values() if s["status"] != "NOT_CONFIGURED"]
        overall = ("NOT_CONFIGURED" if not active else "SUCCESS" if all(s == "SUCCESS" for s in active)
                   else "FAILED" if all(s == "FAILED" for s in active) else "PARTIAL")
        finished = datetime.now(timezone.utc)
        report = {"schema_version": SCHEMA, "pipeline_rule_version": RULE, "synthetic": True,
                  "mode": "fixture", "network_policy": "blocked", "run_id": run_id,
                  "status": overall, "started_at_utc": started,
                  "completed_at_utc": finished.isoformat(),
                  "completed_at_local": finished.astimezone(ZoneInfo("Asia/Taipei")).isoformat(),
                  "fixture_sha256": sha(data), "sources": sources, "followups": queue,
                  "human_review": {"status": "NOT_PERFORMED", "records_modified": False},
                  "daily_json": str(run_dir / "daily.json"),
                  "daily_markdown": str(run_dir / "daily.md")}
        write_new(run_dir / "daily.json", encoded(report))
        write_new(run_dir / "daily.md", render(report).encode("utf-8"))
        sync_directory(run_dir)
        sync_directory(run_dir.parent)
        sync_directory(root)
        state = {"schema_version": SCHEMA, "synthetic": True, "run_id": run_id,
                 "baselines": next_refs, "daily_json": report["daily_json"],
                 "daily_markdown": report["daily_markdown"]}
        temporary = root / f".state-{run_id}.tmp"
        write_new(temporary, encoded(state))
        os.replace(temporary, root / "state.json")
        os.fsync(lock)
        return report
    finally:
        os.close(lock)
