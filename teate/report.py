from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from .model import timestamp, utcnow
from .policy import plan


def cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def summary(ledger, policy: dict) -> dict:
    coverage = ledger.coverage(policy.get("max_scan_age_hours", 48))
    findings = ledger.findings()
    actions = plan(findings, ledger.assets(), policy)
    return {
        "schema_version": 1,
        "generated_at": utcnow(),
        "timezone": policy.get("timezone", "Asia/Tokyo"),
        "counts": {
            "assets": len(coverage),
            "unchecked_assets": sum(c["status"] != "checked" for c in coverage),
            "open": sum(
                f["effective_status"] not in {"resolved", "accepted_risk"} for f in findings
            ),
            "accepted_risk": sum(f["effective_status"] == "accepted_risk" for f in findings),
            "resolved": sum(f["effective_status"] == "resolved" for f in findings),
            "overdue": sum(
                timestamp(a["due_at"]) < datetime.now(UTC) and a["action"] != "accepted_risk"
                for a in actions
            ),
        },
        "coverage": coverage,
        "findings": findings,
        "actions": actions,
    }


def markdown(data: dict) -> str:
    counts = data["counts"]
    zone = ZoneInfo(data.get("timezone", "Asia/Tokyo"))

    def display_time(value):
        return timestamp(value).astimezone(zone).strftime("%Y-%m-%d %H:%M %Z")

    lines = [
        "# Teate — 脆弱性対応状況",
        "",
        f"確認日時: {display_time(data['generated_at'])}",
        "",
        (
            f"資産 {counts['assets']} / 未確認 {counts['unchecked_assets']} / 未解消 {counts['open']} / "
            f"期限超過 {counts['overdue']} / 期限付き例外 {counts['accepted_risk']} / 解消確認 {counts['resolved']}"
        ),
        "",
        "未確認・取得失敗・古い検査は、安全確認として扱いません。",
        "",
        "## 対応候補",
        "",
        "| 優先度 | プロジェクト / 環境 | 問題 | 対応 | 期限 |",
        "|---|---|---|---|---|",
    ]
    for action in data["actions"]:
        lines.append(
            "| "
            + " | ".join(
                cell(v)
                for v in [
                    action["priority"],
                    action["project"] + " / " + action["environment"],
                    action["advisory_id"]
                    + " · "
                    + action["package"]
                    + " "
                    + action["current_version"],
                    action["action"]
                    + (
                        " → " + ", ".join(action["fixed_versions"])
                        if action["fixed_versions"]
                        else ""
                    ),
                    display_time(action["due_at"]),
                ]
            )
            + " |"
        )
    if not data["actions"]:
        lines.extend(
            [
                "",
                "現在取り込まれた結果に未解消の指摘はありません。未確認の資産は下表を確認してください。",
            ]
        )
    lines.extend(
        [
            "",
            "## 確認範囲",
            "",
            "| 資産 | プロジェクト / 環境 | 検査状態 | 未確認の理由 |",
            "|---|---|---|---|",
        ]
    )
    for item in data["coverage"]:
        asset = item["asset"]
        lines.append(
            "| "
            + " | ".join(
                cell(v)
                for v in [
                    asset["id"],
                    asset["project"] + " / " + asset["environment"],
                    item["status"],
                    "; ".join(item["problems"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "完了条件: 対象環境・対象範囲が一致する新しい完全な検査で、指摘の解消を確認できたこと。",
            "",
        ]
    )
    if data.get("transport_errors"):
        lines.extend(["## 同期エラー", "", *["- " + cell(e) for e in data["transport_errors"]], ""])
    if data.get("mac_operations"):
        lines.extend(["## Mac更新", "", *["- " + cell(op) for op in data["mac_operations"]], ""])
    return "\n".join(lines)
