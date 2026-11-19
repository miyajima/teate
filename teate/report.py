from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from .model import timestamp, utcnow
from .policy import plan
from .projects import ACTION_TEXT, overview


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
        "projects": overview(coverage, findings, actions),
    }


def project_lines(projects: list[dict]) -> list[str]:
    lines = ["## プロジェクトごとの次の作業", "",
             "ソース検査の件数は依存ファイル上の検出記録です。コピーの用途・実インストール・本番反映は別途確認します。",
             "修正版候補は対応系列・互換性を確認して選択します。パスの分類だけで指摘を除外しません。", "",
             "Goはgo.modの記載依存を検査します。ビルドや推移依存の追加解決は行いません。", "",
             "| プロジェクト / 環境 | 検査 | 未解消 | まず確認するファイル | 次にすること |",
             "|---|---|---|---|---|"]
    for project in projects:
        count = project["open_count"]
        if count is None:
            count = "未確認"
            if project["known_open_count"]:
                count += f"（既知{project['known_open_count']}件）"
        files = "; ".join(project["files"][:2]) or "—"
        step = project["next_step"]
        if project.get("package_examples"):
            step += " " + "; ".join(project["package_examples"])
        if project["task_count"] > 1:
            step += f" / 全{project['task_count']}作業（詳細はreport）"
        if project.get("problems"):
            step += " 理由: " + "; ".join(project["problems"][:2])
        lines.append("| " + " | ".join(cell(v) for v in [
            project["project"] + " / " + project["environment"],
            "検査済み" if project["scan_status"] == "checked" else "未確認", count, files, step]) + " |")
    return lines + [""]


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
    ]
    if "projects" in data:
        lines.extend(project_lines(data["projects"]))
        lines.extend(["## ファイルごとの作業", ""])
        for project in data["projects"]:
            if not project["tasks"]:
                continue
            lines.extend(["### " + cell(project["project"] + " / " + project["environment"]), ""])
            for task in project["tasks"]:
                packages = ", ".join(p["name"] + " " + p["version"] for p in task["packages"][:3])
                lines.append(f"- {cell(task['file'])}（{task['finding_count']}指摘、{cell(packages)}）: "
                             + cell(task["instruction"]))
            lines.append("")
    lines.extend([
        "## 対応候補",
        "",
        "| 優先度 | プロジェクト / 環境 | 対象ファイル | 問題 | 対応 | 期限 |",
        "|---|---|---|---|---|---|",
    ])
    findings = {f["id"]: f for f in data.get("findings", [])}
    for action in data["actions"]:
        lines.append(
            "| "
            + " | ".join(
                cell(v)
                for v in [
                    action["priority"],
                    action["project"] + " / " + action["environment"],
                    findings.get(action["finding_id"], {}).get("location", "対象範囲未記録"),
                    action["advisory_id"]
                    + " · "
                    + action["package"]
                    + " "
                    + action["current_version"],
                    ACTION_TEXT.get(action["action"], action["action"])
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
