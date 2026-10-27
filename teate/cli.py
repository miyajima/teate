"""CLI and unattended worker. Every integration emits the same evidence receipts."""

from __future__ import annotations

import argparse
import fcntl
import json
import platform
import sys
from pathlib import Path

from . import __version__
from .collect import (
    collect_cloud_run,
    collect_mac,
    discover,
    npm_findings,
    osv_findings,
    scan_cloud_run,
    scan_image,
    scan_source,
    trivy_findings,
)
from .config import load_config
from .feeds import enrich, fetch_kev
from .model import (
    TeateError,
    digest,
    load_json,
    snapshot,
    validate_snapshot,
    write_json,
)
from .policy import merge_decision, plan
from .report import markdown, summary
from .store import Ledger


def output(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="teate", description="脆弱性の検出から実環境での解消確認まで"
    )
    root.add_argument("--version", action="version", version=__version__)
    root.add_argument("--config", default="config/local.json")
    commands = root.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init", help="create an inventory without modifying projects")
    initialize.add_argument("--root", type=Path)
    initialize.add_argument("--output", type=Path, default=Path("config/local.json"))
    commands.add_parser("status")
    report = commands.add_parser("report")
    report.add_argument("--format", choices=["markdown", "json"], default="markdown")
    report.add_argument("--output", type=Path)
    ingest = commands.add_parser("ingest", help="ingest immutable evidence receipts")
    ingest.add_argument("files", nargs="+", type=Path)
    scan = commands.add_parser("scan")
    scan.add_argument("--asset", required=True)
    scan.add_argument("--scanner", choices=["osv", "npm-audit"], default="osv")
    worker = commands.add_parser("run", help="collect this host's assets, scan, and write a report")
    worker.add_argument("--scanner", choices=["osv", "npm-audit"], default="osv")
    worker.add_argument("--publish", help="append evidence to owner/teate on GitHub")
    worker.add_argument("--sync-issues", help="sync remediation issues to owner/teate")
    commands.add_parser("plan")
    mark = commands.add_parser("mark")
    mark.add_argument("finding_id")
    mark.add_argument("--status", required=True)
    mark.add_argument("--reason", required=True)
    exception = commands.add_parser("exception")
    exception.add_argument("finding_id")
    exception.add_argument("--until", required=True)
    exception.add_argument("--reason", required=True)
    commands.add_parser("refresh-feeds")
    normalize = commands.add_parser("normalize", help="convert scanner JSON to a Teate snapshot")
    normalize.add_argument("--asset", required=True)
    normalize.add_argument("--scanner", choices=["osv", "trivy", "npm-audit"], required=True)
    normalize.add_argument("--input", type=Path, required=True)
    normalize.add_argument("--scope", required=True)
    normalize.add_argument("--revision")
    normalize.add_argument("--digest")
    normalize.add_argument("--output", type=Path, required=True)
    normalize.add_argument(
        "--observed-at",
        required=True,
        help="time the original scanner actually ran, including timezone",
    )
    agent = commands.add_parser("launch-agent")
    agent.add_argument("--output", type=Path, required=True)
    agent.add_argument("--repository")
    agent.add_argument("--interval", type=int, default=3600)
    agent.add_argument("--scanner", choices=["osv", "npm-audit"], default="osv")
    upgrade = commands.add_parser("mac-upgrade")
    upgrade.add_argument("--formula", required=True)
    upgrade.add_argument("--apply", action="store_true")
    github = commands.add_parser("github")
    actions = github.add_subparsers(dest="github_action", required=True)
    issues = actions.add_parser("sync-issues")
    issues.add_argument("--repository", required=True)
    issues.add_argument("--apply", action="store_true")
    gate = actions.add_parser("gate")
    gate.add_argument("--repository", required=True)
    gate.add_argument("--pr", type=int, required=True)
    gate.add_argument("--apply", action="store_true")
    publish = actions.add_parser("publish")
    publish.add_argument("--repository", required=True)
    publish.add_argument("--receipt", type=Path, required=True)
    decision = commands.add_parser(
        "evaluate-update", help="evaluate an update fixture without network or mutation"
    )
    decision.add_argument("input", type=Path)
    repair = commands.add_parser("repair", help="prepare isolated candidates; never merge live code")
    repair_actions = repair.add_subparsers(dest="repair_action", required=True)
    prepare = repair_actions.add_parser("prepare")
    prepare.add_argument("--finding", action="append", required=True)
    prepare.add_argument("--target", required=True)
    codex = commands.add_parser("codex", help="inspect subscription-only Codex readiness")
    codex.add_argument("action", choices=["status"])
    agent_cli = commands.add_parser("agent", help="bounded interface for a small-model caller")
    agent_actions = agent_cli.add_subparsers(dest="agent_action", required=True)
    agent_actions.add_parser("brief", help="read a compact authoritative status packet")
    cycle = agent_actions.add_parser("cycle", help="refresh, scan, and return one compact packet")
    cycle.add_argument("--scanner", choices=["osv", "npm-audit"], default="osv")
    cycle.add_argument("--publish")
    cycle.add_argument("--sync-issues")
    render = agent_actions.add_parser(
        "render", help="validate optional focus selection; otherwise use deterministic report"
    )
    render.add_argument("--response", type=Path)
    render.add_argument("--format", choices=["text", "json"], default="text")
    advise = agent_actions.add_parser("advise", help="one optional Codex subscription call")
    advise.add_argument("--model")
    advise.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"])
    advise.add_argument("--format", choices=["text", "json"], default="text")
    return root


def receipt_for(ledger: Ledger, asset: dict, scanner: str, feed: dict | None) -> dict:
    try:
        return _receipt_for(ledger, asset, scanner, feed)
    except (TeateError, OSError, ValueError, KeyError, TypeError) as exc:
        failed = snapshot(
            asset["id"],
            scanner,
            "collection",
            {},
            status="error",
            complete=False,
            message=f"collector failed: {type(exc).__name__}",
        )
        return {
            "schema_version": 1,
            "asset_id": asset["id"],
            "observation": None,
            "scans": [failed],
            "results": [ledger.ingest(failed)],
        }


def _receipt_for(ledger: Ledger, asset: dict, scanner: str, feed: dict | None) -> dict:
    observation = None
    if asset["kind"] == "source":
        scans = scan_source(asset, scanner=scanner)
    elif asset["kind"] == "image":
        scans = [scan_image(asset)]
    elif asset["kind"] == "mac":
        observation, mac_scan = collect_mac(asset)
        scans = [mac_scan]
    else:
        observation = collect_cloud_run(asset)
        scans = [scan_cloud_run(asset, observation)]
    if observation:
        ledger.observe(asset["id"], observation)
    scans = [enrich(scan, feed) for scan in scans]
    results = [ledger.ingest(scan) for scan in scans]
    return {
        "schema_version": 1,
        "asset_id": asset["id"],
        "observation": observation,
        "scans": scans,
        "results": results,
    }


def ingest_file(ledger: Ledger, value: dict) -> list[dict]:
    if "scans" not in value:
        return [ledger.ingest(value)]
    if value.get("schema_version") != 1:
        raise TeateError("Unknown receipt schema")
    asset_id = value["asset_id"]
    ledger.asset(asset_id)
    if not isinstance(value["scans"], list) or not value["scans"]:
        raise TeateError("Receipt must contain a nonempty scan array")
    for scan in value["scans"]:
        validate_snapshot(scan)
    if any(s.get("asset_id") != asset_id for s in value["scans"]):
        raise TeateError("Receipt contains a scan for another asset")
    if value.get("observation"):
        ledger.observe(asset_id, value["observation"])
    return [ledger.ingest(scan) for scan in value["scans"]]


def execute(args) -> int:
    if args.command == "init":
        if args.output.exists():
            raise TeateError("Inventory already exists; refusing to overwrite")
        assets = discover(args.root) if args.root else []
        if platform.system() == "Darwin":
            assets.append(
                {
                    "id": "host:" + platform.node(),
                    "project": "shared-tools",
                    "environment": "mac",
                    "kind": "mac",
                    "host_id": platform.node(),
                    "exposure": "unknown",
                }
            )
        write_json(
            args.output,
            {
                "schema_version": 1,
                "state_dir": "../.teate",
                "assets": assets,
                "policy": {"max_scan_age_hours": 48, "automation": {"enabled": False}},
            },
        )
        output({"config": str(args.output), "assets": len(assets)})
        return 0
    config = load_config(args.config)
    state = Path(config["state_dir"])
    ledger = Ledger(state / "ledger.sqlite3")
    try:
        ledger.register(config["assets"])
        policy = config["policy"]
        feed_file = state / "kev.json"
        agent_mode = args.agent_action if args.command == "agent" else None
        cycle_info = None
        if agent_mode == "cycle":
            cycle_info = {"feed_status": "success"}
            try:
                write_json(feed_file, fetch_kev())
            except (TeateError, OSError, ValueError):
                cycle_info["feed_status"] = "error"
            # Use the same runner and all its existing policy gates.
            args.command = "run"
        try:
            feed = (
                load_json(feed_file)
                if feed_file.exists() and agent_mode not in {"brief", "render", "advise"}
                else None
            )
        except TeateError:
            if agent_mode != "cycle":
                raise
            cycle_info["feed_status"] = "error"
            feed = None
        if args.command == "status":
            output(summary(ledger, policy)["counts"])
        elif args.command == "report":
            data = summary(ledger, policy)
            text = (
                markdown(data)
                if args.format == "markdown"
                else json.dumps(data, ensure_ascii=False, indent=2) + "\n"
            )
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(text)
            else:
                print(text, end="")
        elif args.command == "ingest":
            results = []
            for path in args.files:
                results.extend(ingest_file(ledger, load_json(path)))
            output(results)
        elif args.command == "scan":
            asset = ledger.asset(args.asset)
            receipt = receipt_for(ledger, asset, args.scanner, feed)
            target = state / "receipts" / (digest(receipt) + ".json")
            write_json(target, receipt)
            output(
                {
                    "receipt": str(target),
                    "scans": [
                        {
                            "scope": s["scope"],
                            "status": s["status"],
                            "findings": len(s["findings"]),
                            "message": s["message"],
                        }
                        for s in receipt["scans"]
                    ],
                }
            )
            return int(any(s["status"] != "success" or not s["complete"] for s in receipt["scans"]))
        elif args.command == "run":
            state.mkdir(parents=True, exist_ok=True)
            # Serializes collection, reporting, and transport for one host.
            with (state / "worker.lock").open("a") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise TeateError("Another worker is running") from exc
                receipts, skipped = [], []
                mac_operations = []
                if (
                    platform.system() == "Darwin"
                    and policy.get("mac", {}).get("automatic_formula_updates") is True
                ):
                    from .mac import in_window, upgrade_formula

                    mac_policy = policy["mac"]
                    if in_window(mac_policy.get("maintenance_window", {})):
                        for formula in mac_policy.get("allowed_formulae", []):
                            try:
                                mac_operations.append(
                                    upgrade_formula(
                                        formula, policy, state / "operations", apply=True
                                    )
                                )
                            except TeateError as exc:
                                mac_operations.append(
                                    {"formula": formula, "status": "deferred", "reason": str(exc)}
                                )
                    else:
                        mac_operations.append(
                            {"status": "deferred", "reason": "outside maintenance window"}
                        )
                for asset in config["assets"]:
                    if asset.get("host_id") and asset["host_id"] != platform.node():
                        skipped.append(asset["id"])
                        continue
                    receipt = receipt_for(ledger, asset, args.scanner, feed)
                    target = state / "receipts" / (digest(receipt) + ".json")
                    write_json(target, receipt)
                    receipts.append(receipt)
                transport_errors = []
                if args.publish:
                    from .github import publish_receipt

                    for receipt in receipts:
                        try:
                            publish_receipt(args.publish, receipt)
                        except TeateError as exc:
                            transport_errors.append(str(exc))
                if args.sync_issues:
                    from .github import sync_issues

                    try:
                        sync_issues(ledger, args.sync_issues, apply=True)
                    except TeateError as exc:
                        transport_errors.append(str(exc))
                data = summary(ledger, policy)
                data["transport_errors"] = transport_errors
                data["mac_operations"] = mac_operations
                write_json(state / "summary.json", data)
                (state / "report.md").write_text(markdown(data))
                exit_code = (
                    2
                    if transport_errors
                    else int(
                        any(
                            s["status"] != "success" or not s["complete"]
                            for r in receipts
                            for s in r["scans"]
                        )
                    )
                )
                if agent_mode == "cycle":
                    from .agent import brief

                    if cycle_info["feed_status"] == "error":
                        exit_code = max(exit_code, 1)
                    cycle_info["exit_code"] = exit_code
                    packet = brief(ledger, policy, cycle=cycle_info)
                    write_json(state / "agent" / "brief.json", packet)
                    output(packet)
                else:
                    output(
                        {
                            "counts": data["counts"],
                            "skipped_other_hosts": skipped,
                            "transport_errors": transport_errors,
                            "report": str(state / "report.md"),
                        }
                    )
                return exit_code
        elif args.command == "plan":
            output(plan(ledger.findings(), ledger.assets(), policy))
        elif args.command == "mark":
            ledger.mark(args.finding_id, args.status, args.reason)
            output({"status": args.status})
        elif args.command == "exception":
            ledger.exception(args.finding_id, args.until, args.reason)
            output({"exception_until": args.until})
        elif args.command == "refresh-feeds":
            data = fetch_kev()
            write_json(feed_file, data)
            output({"fetched_at": data["fetched_at"], "released_at": data["data"]["dateReleased"]})
        elif args.command == "normalize":
            raw = load_json(args.input)
            ledger.asset(args.asset)
            if args.scanner == "osv":
                findings, subject = osv_findings(raw), {"type": "source", "revision": args.revision}
                if not args.revision:
                    raise TeateError("Source normalization requires --revision")
            elif args.scanner == "npm-audit":
                findings, subject = (
                    npm_findings(raw, args.scope),
                    {"type": "source", "revision": args.revision},
                )
                if not args.revision:
                    raise TeateError("Source normalization requires --revision")
            else:
                from .model import image_digest

                if not args.digest or not image_digest(args.digest):
                    raise TeateError("Trivy normalization requires a sha256 --digest")
                if image_digest(args.digest) not in {
                    image_digest(d) for d in raw.get("Metadata", {}).get("RepoDigests", [])
                }:
                    raise TeateError("Trivy result does not match --digest")
                findings, subject = trivy_findings(raw), {"type": "image", "digest": args.digest}
            report = snapshot(
                args.asset,
                args.scanner,
                args.scope,
                subject,
                findings,
                complete=not bool(raw.get("errors") or raw.get("error")),
                observed_at=args.observed_at,
            )
            validate_snapshot(report)
            write_json(args.output, report)
            output({"snapshot": str(args.output), "findings": len(findings)})
        elif args.command == "launch-agent":
            from .mac import launch_agent

            args.output.parent.mkdir(parents=True, exist_ok=True)
            state.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(
                launch_agent(
                    Path(args.config),
                    state,
                    interval=args.interval,
                    repository=args.repository,
                    scanner=args.scanner,
                )
            )
            output({"plist": str(args.output), "installed": False})
        elif args.command == "mac-upgrade":
            from .mac import upgrade_formula

            operation = upgrade_formula(
                args.formula, policy, state / "operations", apply=args.apply
            )
            output(operation)
            return int(operation.get("status") in {"failed", "ambiguous"})
        elif args.command == "evaluate-update":
            output(merge_decision(load_json(args.input), policy))
        elif args.command == "codex":
            from .codex import status

            result = status()
            output(result)
            return 0 if result["ready"] else 1
        elif args.command == "repair":
            from .repair import prepare

            result = prepare(ledger, policy, state, args.finding, args.target)
            output(result)
            return int(any(r["status"] != "candidate_ready" for r in result["results"]))
        elif args.command == "agent":
            from .agent import MAX_RESPONSE_BYTES, brief, render

            brief_path = state / "agent" / "brief.json"
            if agent_mode == "brief":
                packet = brief(ledger, policy)
                write_json(brief_path, packet)
                output(packet)
            else:
                original = load_json(brief_path) if brief_path.exists() else None
                cycle = original.get("cycle") if isinstance(original, dict) else None
                current = brief(ledger, policy, cycle=cycle)
                response_text = None
                transport = None
                if agent_mode == "advise":
                    from .codex import select

                    original = current
                    write_json(brief_path, original)
                    transport = select(original, model=args.model, effort=args.effort)
                    response_text = transport.pop("response_text")
                    # Revalidate all facts after the potentially slow model call.
                    current = brief(ledger, policy, cycle=cycle)
                elif args.response:
                    try:
                        with args.response.open() as file:
                            response_text = file.read(MAX_RESPONSE_BYTES + 1)
                    except (OSError, UnicodeError):
                        response_text = ""  # Invalid input takes the model-free path.
                rendered = render(current, original=original, response_text=response_text)
                if transport is not None:
                    rendered["codex"] = transport
                write_json(state / "agent" / "report.json", rendered)
                if args.format == "json":
                    output(rendered)
                else:
                    print(rendered["text"], end="")
        elif args.command == "github":
            from .github import (
                apply_merge,
                inspect_patch_pr,
                publish_receipt,
                sync_issues,
            )

            if args.github_action == "sync-issues":
                output(sync_issues(ledger, args.repository, apply=args.apply))
            elif args.github_action == "gate":
                if args.repository not in {a.get("repository") for a in config["assets"]}:
                    raise TeateError("Repository is not registered in this inventory")
                update, decision = inspect_patch_pr(args.repository, args.pr, policy)
                output(
                    apply_merge(args.repository, args.pr, update, decision)
                    if args.apply
                    else {"update": update, "decision": decision}
                )
            else:
                receipt = load_json(args.receipt)
                ingest_file(ledger, receipt)  # Validate the receipt before sending it.
                output(publish_receipt(args.repository, receipt))
        return 0
    finally:
        ledger.close()


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return execute(args)
    except (TeateError, OSError, ValueError, KeyError) as exc:
        print(f"teate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
