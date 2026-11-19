"""Deterministic work lists; path hints never suppress findings or prove deployment."""
from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath

PRIORITY = {"urgent": 0, "high": 1, "normal": 2}
ACTION_TEXT = {
    "prepare_update_pr": "依存定義とlockを整合させて修正版へ更新し、テスト後に対象を再検査する。",
    "investigate_fix": "公式勧告で修正方法を確認する。backport済みなら修正記録・実体を照合する。",
    "isolate_and_investigate": "影響する実行環境を隔離し、証跡を保全して悪意あるパッケージを調査する。",
    "review_prepared_candidate": "作成済み修正候補の差分・互換性・未実行テストをレビューする。",
    "complete_required_tests": "修正候補の未完了テストを実行し、結果を確認して再検査する。",
    "verify_deployed_runtime": "対象環境の配備先・稼働版を確認し、同じ実体を再検査する。配備完了は未確認。",
    "resolve_blocker_and_rescan": "記録されたブロックを解消し、同じ対象を再検査する。",
    "accepted_risk": "期限付き例外の期限と根拠を確認し、期限前に再評価する。",
}


def scope_hint(location: str) -> str:
    parts = PurePosixPath(location.replace("\\", "/")).parts
    review = {".worktrees", ".agent-worktrees", ".local", ".plans", ".tools",
              "backup", "backups", "archive", "archives", "fixtures", "templates",
              "examples", "testdata"}
    return "review" if any(p in review or "backup" in p.lower() for p in parts) else "source_candidate"


def coverage_step(problems: list[str]) -> tuple[str, str]:
    reason = " ".join(problems)
    if "Go module input missing" in reason or "cannot parse dependency file" in reason:
        return "fix_scanner_input", "解析できない依存ファイルを確認する。Goは同じ場所のgo.modを指定し、対象だけ再検査する。"
    if "no supported dependency manifest found" in reason:
        return "check_dependency_inputs", "依存宣言と配置先を確認する。lockを用意するか、依存を持たない資料・ツールなら対象外を明示する。"
    if "osv-scanner not installed" in reason:
        return "install_scanner", "OSV-Scannerの導入とPATHを確認し、対象だけ再検査する。"
    if "access denied by network policy" in reason:
        return "restore_scan_access", "通信制限の範囲と利用可能な検査方法を確認する。制限を緩めず、未確認の言語を残す。"
    if "stale" in reason or "never scanned" in reason:
        return "scan_required", "対象の登録内容を確認し、新しい検査を実行する。"
    return "diagnose_scan_failure", "未確認の理由を診断して対象だけ再検査する。指摘なし・安全確認済みとは扱わない。"


def overview(coverage: list[dict], findings: list[dict], actions: list[dict]) -> list[dict]:
    by_finding = {f["id"]: f for f in findings}
    by_asset = defaultdict(list)
    for action in actions:
        by_asset[action["asset_id"]].append(action)
    resolved = defaultdict(int)
    for finding in findings:
        if finding["effective_status"] == "resolved":
            resolved[finding["asset_id"]] += 1
    projects = []
    for entry in coverage:
        asset = entry["asset"]
        project_actions = by_asset[asset["id"]]
        grouped = {}
        for action in project_actions:
            finding = by_finding[action["finding_id"]]
            location = finding.get("location", "") or finding.get("scope", "対象範囲未記録")
            key = (location, action["action"])
            if key not in grouped:
                hint = scope_hint(location)
                instruction = ACTION_TEXT.get(action["action"], "記録された対応内容を確認する。")
                if action["action"] == "prepare_update_pr" and asset["kind"] != "source":
                    instruction = {
                        "image": "イメージのOS・依存を修正して再ビルドし、digestを固定して再検査する。稼働先への反映は別途確認する。",
                        "cloud-run": "稼働revisionのイメージ元を修正・再ビルドし、配備後のrevisionとdigestを照合して再検査する。",
                        "mac": "対象のOS・ツールの公式修正版と稼働状態を確認して更新する。棚卸しだけでCVE解消としない。",
                    }[asset["kind"]]
                if hint == "review" and action["action"] not in {"isolate_and_investigate", "accepted_risk"}:
                    instruction = "作業コピー・例示用と思われるパス。現用かを確認し、現用なら次を実施する: " + instruction
                if action["action"] == "prepare_update_pr" and location.endswith("requirements.txt"):
                    instruction += " requirements.txtの記載と実インストール版を照合する。"
                grouped[key] = {"file": location, "action": action["action"], "scope_hint": hint,
                                "instruction": instruction, "priority": action["priority"],
                                "finding_count": 0, "packages": [], "finding_ids": []}
            task = grouped[key]
            task["finding_count"] += 1
            task["finding_ids"].append(action["finding_id"])
            if PRIORITY[action["priority"]] < PRIORITY[task["priority"]]:
                task["priority"] = action["priority"]
            package = {"name": action["package"], "version": action["current_version"],
                       "fixed_versions": action["fixed_versions"]}
            if package not in task["packages"]:
                task["packages"].append(package)
        tasks = sorted(grouped.values(), key=lambda t: (
            PRIORITY[t["priority"]], t["scope_hint"] == "review", t["file"], t["action"]))
        active = [a for a in project_actions if a["action"] != "accepted_risk"]
        checked = entry["status"] == "checked"
        if not checked:
            code, instruction = coverage_step(entry["problems"])
        elif tasks:
            code, instruction = tasks[0]["action"], tasks[0]["instruction"]
        else:
            code = "no_open_findings"
            instruction = "今回の検査範囲に未解消の指摘なし。対象環境・検査範囲を確認する。"
        examples = []
        for task in tasks[:1]:
            for package in task["packages"][:2]:
                text = package["name"] + " " + package["version"]
                if package["fixed_versions"]:
                    text += " → 修正版候補 " + ", ".join(package["fixed_versions"][:3])
                examples.append(text)
        projects.append({
            "asset_id": asset["id"], "project": asset["project"],
            "environment": asset["environment"], "kind": asset["kind"],
            "scan_status": entry["status"], "open_count": len(active) if checked else None,
            "known_open_count": len(active), "resolved_count": resolved[asset["id"]],
            "runtime_status": "unverified" if asset["kind"] == "source" else "see_asset_evidence",
            "problems": entry["problems"],
            "next_action": code, "next_step": instruction,
            "priority": min((a["priority"] for a in active), key=PRIORITY.get, default="normal"),
            "task_count": len(tasks), "files": list(dict.fromkeys(t["file"] for t in tasks)),
            "package_examples": examples, "tasks": tasks,
        })
    def order(project):
        if project["priority"] == "urgent":
            stage = 0
        elif project["scan_status"] != "checked" and project["next_action"] != "check_dependency_inputs":
            stage = 1
        elif project["priority"] == "high":
            stage = 2
        elif project["known_open_count"]:
            stage = 3
        elif project["scan_status"] != "checked":
            stage = 4
        else:
            stage = 5
        return stage, project["project"], project["environment"], project["asset_id"]

    return sorted(projects, key=order)
