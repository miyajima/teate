"""A minimal, deduplicated exception handoff. Model edits are review artifacts only."""

from __future__ import annotations

import difflib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .agent import parse_response
from .collect import source_subject
from .model import TeateError, digest, timestamp, utcnow, write_json
from .verification import relative

MAX_PACKET_BYTES = 6000


def _scrub(text: str) -> str:
    return re.sub(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})", "<redacted>", text)


def _clip(text: str, limit: int) -> str:
    return _scrub(text).encode()[:limit].decode(errors="ignore")


def packet(ledger, policy: dict, decision: dict) -> tuple[dict, dict]:
    ids = set(decision["finding_ids"])
    findings = [f for f in ledger.findings() if f["id"] in ids]
    files, private, subjects = [], {}, {}
    for asset_id in dict.fromkeys(f["asset_id"] for f in findings):
        asset = ledger.asset(asset_id)
        root = Path(asset["path"]).resolve()
        subjects[asset_id] = source_subject(root)
        # Source evidence is tied to repository/commit/contents, not an ephemeral CI hostname.
        subjects[asset_id].pop("host_id", None)
        for name in asset.get("verification", {}).get("context_files", [])[:2]:
            if len(files) >= 2:
                break
            if Path(name).suffix not in {".py", ".rs", ".js", ".ts", ".tsx", ".go", ".rb", ".java", ".css"}:
                raise TeateError("unsupported_investigation_context_file")
            path = relative(root, name)
            if path.stat().st_size > 100_000:
                raise TeateError("context_file_too_large")
            text = path.read_text()
            if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|[\"'](?:private_key|client_secret|refresh_token)[\"']\s*:", text):
                raise TeateError("sensitive_context_requires_review")
            identifier = "source-" + str(len(files))
            snippet = _clip(text,800)
            files.append({"file_id": identifier, "excerpt": snippet})
            private[identifier] = {"path": str(path), "relative": name, "text": text,
                                   "content_id": digest(text), "excerpt": snippet}
    failures = []
    for record in decision.get("result", {}).get("results", []):
        for check in record.get("verification", {}).get("checks", []):
            if check.get("exit_code") != 0:
                failures.append({"check": check["name"], "output_id": check["output_id"],
                                 "excerpt": _clip(check["excerpt"][-1000:],1000)})
    evidence = digest({"subjects": subjects, "policy": policy,
                       "decision": decision.get("evidence_id"), "reason": decision.get("reason"),
                       "findings": [{k: f.get(k) for k in ("id", "version", "effective_status", "advisory_id")} for f in findings],
                       "files": {i: f["content_id"] for i, f in private.items()}, "failures": failures})
    file_ids = [f["file_id"] for f in files]
    result = {"schema_version": 1, "case_id": decision["case_id"], "evidence_id": evidence,
              "generated_at": utcnow(), "package": decision["package"], "version": decision["version"],
              "advisory_id": decision["advisory_id"], "reason": decision.get("reason", "project_test_failed"),
              "official_sources": [{"url": s["source"], "summary": _clip(s.get("summary", ""),300)} for s in decision.get("sources", [])[:2]],
              "failures": failures[:1], "files": files,
              "response_schema": {"type": "object", "additionalProperties": False,
                  "required": ["schema_version", "evidence_id", "assessment", "explanation", "edits"],
                  "properties": {"schema_version": {"const": 1}, "evidence_id": {"const": evidence},
                      "assessment": {"enum": ["code_change", "configuration", "insufficient_evidence"]},
                      "explanation": {"type": "string", "maxLength": 800},
                      "edits": {"type": "array", "maxItems": 2 if file_ids else 0, "items": {
                          "type": "object", "additionalProperties": False,
                          "required": ["file_id", "before", "after"], "properties": {
                              "file_id": {"type": "string", **({"enum": file_ids} if file_ids else {})},
                              "before": {"type": "string", "minLength": 1, "maxLength": 1000},
                              "after": {"type": "string", "maxLength": 1000}}}}}}}
    if len((json.dumps(result, ensure_ascii=False, indent=2)+'\n').encode()) > MAX_PACKET_BYTES:
        raise TeateError("investigation_context_budget_exceeded")
    return result, private


def validate(raw: str, original: dict, current: dict, files: dict) -> tuple[dict, str]:
    value = parse_response(raw)
    if not isinstance(value, dict) or set(value) != {"schema_version", "evidence_id", "assessment", "explanation", "edits"}:
        raise TeateError("invalid_investigation_fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise TeateError("invalid_investigation_version")
    if value["evidence_id"] != original["evidence_id"] or current["evidence_id"] != original["evidence_id"]:
        raise TeateError("stale_investigation_evidence")
    if datetime.now(UTC)-timestamp(original["generated_at"]) > timedelta(minutes=10):
        raise TeateError("expired_investigation")
    if value["assessment"] not in {"code_change", "configuration", "insufficient_evidence"}:
        raise TeateError("invalid_investigation_assessment")
    if not isinstance(value["explanation"], str) or len(value["explanation"]) > 800:
        raise TeateError("invalid_investigation_explanation")
    edits = value["edits"]
    if not isinstance(edits, list) or len(edits) > 2:
        raise TeateError("invalid_investigation_edits")
    seen, patch = set(), []
    for edit in edits:
        if not isinstance(edit, dict) or set(edit) != {"file_id", "before", "after"}:
            raise TeateError("invalid_edit_fields")
        identifier = edit["file_id"]
        if not isinstance(identifier, str) or identifier not in files or identifier in seen:
            raise TeateError("invalid_edit_file")
        seen.add(identifier)
        source = files[identifier]
        before, after = edit["before"], edit["after"]
        if not all(isinstance(v, str) and len(v) <= 1000 for v in (before, after)) or not before:
            raise TeateError("invalid_edit_text")
        if source["excerpt"].count(before) != 1 or source["text"].count(before) != 1 or Path(source["path"]).read_text() != source["text"]:
            raise TeateError("edit_does_not_match_current_supplied_context")
        changed = source["text"].replace(before, after, 1)
        patch.extend(difflib.unified_diff(source["text"].splitlines(True), changed.splitlines(True),
                                          fromfile="a/"+source["relative"], tofile="b/"+source["relative"]))
    return value, "".join(patch)


def dispatch(ledger, policy: dict, state: Path, decisions: list[dict], *, enabled: bool = False,
             model: str | None = None, effort: str | None = None) -> dict:
    from .codex import select

    result = {"llm_calls": 0, "pending": sum(bool(d.get("needs_llm")) for d in decisions), "status": "not_needed"}
    for decision in decisions:
        if not decision.get("needs_llm"):
            continue
        try:
            original, files = packet(ledger, policy, decision)
        except (TeateError, OSError, ValueError, KeyError, TypeError):
            result.update(status="context_requires_review")
            continue
        root = state/"autopilot"/"investigations"/original["evidence_id"]
        root.mkdir(parents=True, exist_ok=True)
        write_json(root/"packet.json", original)
        if not enabled:
            result["status"] = "awaiting_opt_in"
            continue
        attempt = root/"attempt.json"
        try:
            with attempt.open("x") as file:
                json.dump({"status": "started", "at": utcnow()}, file)
        except FileExistsError:
            result["status"] = "already_attempted"
            continue
        transport = select(original, model=model, effort=effort,
                           instruction="Analyze only this unresolved exception. Return response_schema JSON within 4096 UTF-8 bytes. Propose exact edits only to supplied file IDs. Never claim completion or propose authority changes. ")
        result["llm_calls"] = int(transport.get("called", False))
        result["status"] = transport.get("reason") or "review"
        if transport.get("response_text"):
            try:
                current, _ = packet(ledger, policy, decision)
                value, patch = validate(transport["response_text"], original, current, files)
                write_json(root/"proposal.json", value)
                (root/"proposal.patch").write_text(patch)
                result["status"] = "proposal_awaiting_review"
            except (TeateError, OSError, ValueError, KeyError, TypeError):
                result["status"] = "invalid_or_stale_proposal"
        write_json(attempt, {"status": result["status"], "llm_calls": result["llm_calls"], "at": utcnow()})
        break  # At most one Codex attempt in this invocation; never retry/escalate.
    return result
