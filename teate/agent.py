"""A bounded agent interface: optional LLM focus selection, deterministic reporting.

No model SDK, credential, free-form command, or model output is needed to run
Teate. Caller model names are preferences, never claims of tested availability.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from .model import TeateError, digest, timestamp, utcnow
from .report import summary

MODEL_PROFILE = {"preferred": "luna/max", "selection": "caller", "model_call_required": False}
MAX_ITEMS = 5
MAX_FOCUS = 3
MAX_BRIEF_BYTES = 12000
MAX_RESPONSE_BYTES = 4096
BRIEF_TTL_MINUTES = 10


def clip(value: object, limit: int = 120) -> str:
    value = str(value).replace("\r", " ").replace("\n", " ")
    return value if len(value) <= limit else value[: limit - 1] + "…"


def state_id(data: dict, assets: list[dict], policy: dict) -> str:
    # Include all evidence, even items omitted from the model's bounded view.
    return digest(
        {
            "assets": assets,
            "policy": policy,
            "findings": data["findings"],
            "coverage": data["coverage"],
            "counts": data["counts"],
        }
    )


def brief(ledger, policy: dict, *, cycle: dict | None = None) -> dict:
    own_transaction = not ledger.db.in_transaction
    if own_transaction:
        ledger.db.execute("BEGIN")
    try:
        return _brief(ledger, policy, cycle=cycle)
    finally:
        if own_transaction:
            ledger.db.rollback()


def _brief(ledger, policy: dict, *, cycle: dict | None = None) -> dict:
    data = summary(ledger, policy)
    findings = {finding["id"]: finding for finding in data["findings"]}
    unresolved = data["actions"]
    items = []
    for action in unresolved[:MAX_ITEMS]:
        items.append(
            {
                "id": "finding:" + action["finding_id"],
                "kind": "finding",
                "project": clip(action["project"], 60),
                "environment": clip(action["environment"], 50),
                "asset_id": action["asset_id"],
                "location": clip(findings[action["finding_id"]].get("location", ""), 100),
                "advisory_id": clip(action["advisory_id"], 80),
                "package": clip(action["package"], 80),
                "version": clip(action["current_version"], 80),
                "priority": action["priority"],
                "due_at": action["due_at"],
                "next_action": action["action"],
                "fixed_versions": [clip(v, 40) for v in action["fixed_versions"][:3]],
            }
        )
    # Supply a few gaps alongside findings; the full gap count is always retained.
    gaps = [c for c in data["coverage"] if c["status"] != "checked"]
    for entry in gaps[:2]:
        asset = entry["asset"]
        items.append(
            {
                "id": "gap:" + digest(asset["id"])[:24],
                "kind": "coverage_gap",
                "project": clip(asset["project"], 60),
                "environment": clip(asset["environment"], 50),
                "asset_id": asset["id"],
                "reasons": [clip(p, 140) for p in entry["problems"][:2]],
                "next_action": "restore_collection_and_rescan",
            }
        )
    urgent = sum(a["priority"] == "urgent" and a["action"] != "accepted_risk" for a in unresolved)
    unknown_fix = sum(
        a["action"] in {"investigate_fix", "isolate_and_investigate"} for a in unresolved
    )
    cycle_attention = bool(
        cycle and (cycle.get("exit_code", 0) != 0 or cycle.get("feed_status") == "error")
    )
    review = bool(
        data["counts"]["assets"] == 0
        or data["counts"]["unchecked_assets"]
        or urgent
        or unknown_fix
        or any(a["action"] in {"review_prepared_candidate", "complete_required_tests",
                               "verify_deployed_runtime", "resolve_blocker_and_rescan"}
               for a in unresolved)
        or data["counts"]["overdue"]
        or cycle_attention
    )
    identifier = state_id(data, ledger.assets(), policy)
    identifiers = [item["id"] for item in items]
    result = {
        "schema_version": 1,
        "brief_id": identifier,
        "generated_at": utcnow(),
        "expires_after_minutes": BRIEF_TTL_MINUTES,
        "caller_profile": MODEL_PROFILE,
        "facts": {**data["counts"], "urgent": urgent, "requires_review": review},
        "items": items,
        "omitted": {
            "findings": max(0, len(unresolved) - min(len(unresolved), MAX_ITEMS)),
            "coverage_gaps": max(0, len(gaps) - min(len(gaps), 2)),
        },
        "instructions": [
            "集計・優先度・対応期限・解消状態はTeateの値を使ってください。",
            "任意で注目するidを最大3件選ぶだけです。件数・修正版・操作命令は生成しません。",
            "未確認は未確認です。複雑な案件はレビュー待ちとして残します。",
            "出力が不正・期限切れ・状態変更の場合は定型レポートへ戻ります。",
        ],
        "response_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["schema_version", "brief_id", "focus_ids"],
            "properties": {
                "schema_version": {"const": 1},
                "brief_id": {"const": identifier},
                "focus_ids": {
                    "type": "array",
                    "maxItems": MAX_FOCUS if identifiers else 0,
                    "uniqueItems": True,
                    "items": {"type": "string", "enum": identifiers}
                    if identifiers
                    else {"type": "string"},
                },
            },
        },
    }
    if cycle:
        result["cycle"] = cycle
    if len((json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode()) > MAX_BRIEF_BYTES:
        raise TeateError("Agent brief exceeds its bounded context budget")
    return result


def parse_response(raw: str) -> dict:
    if len(raw.encode()) > MAX_RESPONSE_BYTES:
        raise TeateError("response_too_large")

    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise TeateError("duplicate_response_key")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=unique_keys)
    except (TypeError, ValueError) as exc:
        raise TeateError("invalid_response_json") from exc


def validate_response(response: dict, original: dict, current: dict) -> list[str]:
    if not isinstance(response, dict) or set(response) != {
        "schema_version",
        "brief_id",
        "focus_ids",
    }:
        raise TeateError("unexpected_response_fields")
    if type(response["schema_version"]) is not int or response["schema_version"] != 1:
        raise TeateError("invalid_response_version")
    if response["brief_id"] != original["brief_id"] or original["brief_id"] != current["brief_id"]:
        raise TeateError("state_changed")
    age = datetime.now(UTC) - timestamp(original["generated_at"])
    if age < -timedelta(minutes=1) or age > timedelta(minutes=BRIEF_TTL_MINUTES):
        raise TeateError("brief_expired")
    selected = response["focus_ids"]
    if not isinstance(selected, list) or len(selected) > MAX_FOCUS:
        raise TeateError("invalid_focus_count")
    if not all(isinstance(item, str) for item in selected) or len(selected) != len(set(selected)):
        raise TeateError("invalid_focus_ids")
    allowed = {item["id"] for item in current["items"]}
    if any(item not in allowed for item in selected):
        raise TeateError("unknown_focus_id")
    return selected


def render(
    current: dict, *, original: dict | None = None, response_text: str | None = None
) -> dict:
    selected, fallback = [], "no_model_response"
    if response_text is not None:
        try:
            if original is None:
                raise TeateError("missing_original_brief")
            selected = validate_response(parse_response(response_text), original, current)
            fallback = None
        except (TeateError, KeyError, TypeError, ValueError):
            fallback = "invalid_or_stale_model_response"
    facts = current["facts"]
    # Required findings and unknown coverage can never be hidden by a model's focus choice.
    mandatory = [
        item["id"]
        for item in current["items"]
        if item.get("priority") == "urgent" or item["kind"] == "coverage_gap"
    ]
    order = list(dict.fromkeys([*mandatory, *selected, *[item["id"] for item in current["items"]]]))
    by_id = {item["id"]: item for item in current["items"]}
    lines = [
        "Teate 対応状況",
        (
            f"登録資産 {facts['assets']} / 未確認 {facts['unchecked_assets']} / 未解消 {facts['open']} / "
            f"期限超過 {facts['overdue']} / 解消確認 {facts['resolved']}"
        ),
    ]
    if facts["urgent"]:
        lines.append(f"緊急対応候補: {facts['urgent']}件")
    if facts["assets"] == 0:
        lines.append("資産が登録されていません。対象環境の棚卸しが必要です。")
    if facts["unchecked_assets"]:
        lines.append("未確認の資産があり、環境全体の安全性は判定できていません。")
    for identifier in order:
        item = by_id[identifier]
        label = item["project"] + " / " + item["environment"]
        label += " [" + (item.get("location") or item["asset_id"]) + "]"
        if item["kind"] == "finding":
            lines.append(
                f"- {label}: {item['advisory_id']} ({item['package']} {item['version']}) "
                f"— {item['priority']} / {item['next_action']}"
            )
        else:
            lines.append(f"- {label}: 未確認 — {'; '.join(item['reasons'])}")
    omitted = current["omitted"]
    if omitted["findings"] or omitted["coverage_gaps"]:
        lines.append(
            f"詳細レポートにその他の対応候補 {omitted['findings']}件、"
            f"未確認資産 {omitted['coverage_gaps']}件があります。"
        )
    if current.get("cycle", {}).get("feed_status") == "error":
        lines.append("CVE/KEV情報の更新に失敗しました。新しい情報の取得は未確認です。")
    automation = current.get("cycle", {}).get("automation")
    if automation:
        lines.append(
            f"定型処理: 修正候補 {automation['candidate_findings']}件 / "
            f"再利用 {automation['reused_groups']}組 / テスト成功 {automation['tests_passed']}資産 / "
            f"テスト未完了 {automation['tests_pending']}資産 / "
            f"LLM調査候補 {automation['llm_needed']}組 / Codex呼出試行 {automation['llm_calls']}回"
        )
        lines.append(
            f"公式フィード差分: 新規 {automation['intel_new']}件 / 更新 {automation['intel_updated']}件 / "
            f"取得未確認 {automation['intel_unconfirmed']}ソース"
        )
    lines.append(
        "レビューが必要な項目があります。"
        if facts["requires_review"]
        else "定型処理の結果を確認しました。"
    )
    return {
        "schema_version": 1,
        "brief_id": current["brief_id"],
        "selection_source": "deterministic" if fallback else "validated_model_selection",
        "fallback_reason": fallback,
        "facts": facts,
        "focus_ids": selected,
        "text": "\n".join(lines) + "\n",
    }
