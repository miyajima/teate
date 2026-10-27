"""Policy-bound repair execution, reconciliation, deployment and runtime evidence."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import subprocess
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import publication, repair, source
from .collect import collect_cloud_run, scan_cloud_run, scan_image, scan_source, source_subject
from .jobs import TERMINAL, Jobs
from .model import TeateError, digest, timestamp
from .verification import verify

NEXT = {
    "ready": "設定済みの検証と反映を実行します",
    "blocked": "理由に示した設定・テスト・接続を確認して同じrunを再開してください",
    "awaiting_deployment": "deploy・observe・health・rollbackと稼働資産を登録してください",
    "awaiting_ci": "同じコミットの必須CIとマージ結果を確認して再開してください",
    "verification_pending": "稼働先との接続を復旧し、同じrunを再検査してください",
    "uncertain": "観測で操作結果を確認するまで変更操作は再送しません",
    "review": "自動継続できません。履歴の理由と証跡を確認してください",
    "stale": "ソース・設定が変わったため、新しい候補を作成してください",
    "rolled_back": "復旧を確認しました。脆弱性は未解消として次の修復を検討してください",
    "verified": "対象の実環境で修復を確認しました",
}


@contextmanager
def asset_lock(state, asset_id):
    directory = state / "locks"
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / (digest(asset_id) + ".lock")).open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise TeateError("asset_repair_already_running") from exc
        yield


def compact(run):
    return {
        k: run.get(k)
        for k in ("id", "asset_id", "status", "phase", "reason", "next_action", "updated_at")
    }


def authorize(asset, policy, record):
    settings = asset.get("remediation", {})
    automation = policy.get("automation", {})
    if settings.get("enabled") is not True or automation.get("enabled") is not True:
        raise TeateError("asset_automatic_remediation_not_enabled")
    if settings.get("mode") not in ("local", "github"):
        raise TeateError("explicit_local_or_github_deployment_mode_required")
    allowed = set(automation.get("allowed_packages", []))
    if not record.get("update", {}).get("packages") or any(
        p["name"] not in allowed for p in record["update"]["packages"]
    ):
        raise TeateError("every_updated_package_must_be_explicitly_allowed")
    published = record["update"].get("published_at")
    if not published or datetime.now(UTC) - timestamp(published) < timedelta(
        hours=automation.get("minimum_release_age_hours", 336)
    ):
        raise TeateError("release_waiting_period_not_satisfied")
    if record.get("policy_id") != digest(policy) or record.get("asset_id_at_prepare") != digest(
        asset
    ):
        raise TeateError("source_or_policy_changed_reprepare")
    if not asset.get("host_id"):
        # The prepared subject records this host even for older inventories.
        import platform

        if record.get("original_subject", {}).get("host_id") != platform.node():
            raise TeateError("source_host_unverified")
    if settings["mode"] == "github":
        base = settings.get("base_branch", "main")
        if base not in automation.get("allowed_base_branches", ["main"]):
            raise TeateError("github_base_branch_not_allowed")
        if not automation.get("required_checks"):
            raise TeateError("commit_specific_required_checks_must_be_configured")
        # API publishing must use the explicitly registered repository.
        if asset.get("repository", "").removeprefix("https://github.com/").removesuffix(
            ".git"
        ) != settings.get("repository"):
            raise TeateError("github_repository_not_registered")
    return settings


def hook_spec(spec):
    if not isinstance(spec, dict):
        raise TeateError("deployment_hook_not_registered")
    argv = spec.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(a, str) and "\x00" not in a for a in argv)
    ):
        raise TeateError("deployment_hook_requires_literal_argv")
    executable = Path(argv[0])
    if not executable.is_absolute() or not executable.is_file():
        raise TeateError("deployment_hook_requires_absolute_executable")
    if hashlib.sha256(executable.read_bytes()).hexdigest() != spec.get("sha256"):
        raise TeateError("deployment_hook_executable_hash_changed")
    # Pin additional operator-owned scripts/config consumed by the executable.
    for name, expected in spec.get("files", {}).items():
        path = Path(name)
        if not path.is_absolute() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise TeateError("deployment_hook_input_hash_changed")
    timeout = spec.get("timeout_seconds", 120)
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise TeateError("deployment_hook_timeout_invalid")
    cwd = spec.get("cwd")
    if cwd and (not Path(cwd).is_absolute() or not Path(cwd).is_dir()):
        raise TeateError("deployment_hook_cwd_invalid")
    return argv, timeout, cwd


def hook(spec, run, *, release_id=""):
    argv, timeout, cwd = hook_spec(spec)
    values = {
        "candidate": run["record"]["worktree"],
        "run_id": run["id"],
        "candidate_id": digest(run["record"]["candidate_files"]),
        "release_id": release_id,
        "head_sha": run.get("publication", {}).get("head_sha", ""),
    }
    result_argv = []
    for argument in argv:
        # Only exact placeholders. No shell evaluation or format-string expressions.
        for name, value in values.items():
            argument = argument.replace("{" + name + "}", value)
        result_argv.append(argument)
    allowed_env = spec.get("env_names", [])
    if not isinstance(allowed_env, list) or not all(isinstance(k, str) for k in allowed_env):
        raise TeateError("deployment_hook_env_names_invalid")
    env = {
        k: os.environ[k]
        for k in (
            "PATH",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            *allowed_env,
        )
        if k in os.environ
    }
    # Operator hooks are trusted control-plane programs, not project tests. Their
    # output contract contains identities/status only; raw logs never enter history.
    from .process import capture

    result = capture(result_argv, cwd=cwd, env=env, timeout=timeout, limit=12000)
    raw = result["raw"]
    if result["exit_code"] or result["timed_out"] or result["output_limited"]:
        raise TeateError("deployment_hook_outcome_unconfirmed")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise TeateError("deployment_hook_invalid_receipt") from exc
    if not isinstance(data, dict) or data.get("run_id") != run["id"]:
        raise TeateError("deployment_hook_run_identity_mismatch")
    keys = {
        "status",
        "deployment",
        "run_id",
        "candidate_id",
        "release_id",
        "previous_release_id",
        "healthy",
        "runtime_digests",
    }
    if set(data) - keys:
        raise TeateError("deployment_hook_unexpected_receipt_fields")
    return data


def runtime_verify(ledger, asset, run, observed):
    settings, record = asset["remediation"], run["record"]
    deployment = run["deployment"]
    if (
        observed.get("deployment") != "applied"
        or observed.get("status") != "success"
        or observed.get("candidate_id") != digest(record["candidate_files"])
        or observed.get("release_id") != deployment.get("release_id")
    ):
        raise TeateError("deployed_release_or_candidate_not_verified")
    checks = []
    expected = settings.get("runtime_assets", [])
    if not isinstance(expected, list) or not expected or len(set(expected)) != len(expected):
        raise TeateError("runtime_assets_not_registered")
    for identifier in expected:
        runtime = ledger.asset(identifier)
        if runtime["kind"] == "source":
            # The trusted observer binds this source snapshot to the active release.
            subject = source_subject(Path(runtime["path"]))
            wanted = record["subject"]["lockfile_hashes"]
            if not wanted or subject["lockfile_hashes"] != wanted:
                raise TeateError("runtime_source_lockfiles_do_not_match_candidate")
            scans = scan_source(runtime, scanner=record["scanner"])
        elif runtime["kind"] == "image":
            from .model import image_digest

            if image_digest(runtime.get("image", "")) not in deployment.get("runtime_digests", []):
                raise TeateError("runtime_image_not_bound_to_deployment")
            scans = [scan_image(runtime)]
        elif runtime["kind"] == "cloud-run":
            observation = collect_cloud_run(runtime)
            if observation.get("status") != "success" or set(observation.get("images", [])) != set(
                deployment.get("runtime_digests", [])
            ):
                raise TeateError("all_reachable_cloud_run_revisions_not_verified")
            ledger.observe(identifier, observation)
            scans = [scan_cloud_run(runtime, observation)]
        else:
            raise TeateError("runtime_asset_kind_unsupported")
        if not scans or any(s["status"] != "success" or not s["complete"] for s in scans):
            raise TeateError("runtime_scan_incomplete")
        selected = [f for f in ledger.findings() if f["id"] in record["finding_ids"]]
        aliases = {a for f in selected for a in [f["advisory_id"], *f.get("aliases", [])]}
        if any(
            aliases & {v["advisory_id"], *v.get("aliases", [])}
            for s in scans
            for v in s["findings"]
        ):
            raise TeateError("target_advisory_remains_in_runtime")
        for scan in scans:
            checks.append(ledger.ingest(scan))
    # Source and production are distinct facts. A deployment must not silently
    # close a still-vulnerable source checkout, or vice versa.
    source_asset = ledger.asset(asset["id"])
    if (
        source_subject(Path(source_asset["path"]))["lockfile_hashes"]
        != record["subject"]["lockfile_hashes"]
    ):
        raise TeateError("runtime_verified_source_sync_still_required")
    scans = scan_source(source_asset, scanner=record["scanner"])
    scopes = {f["scope"] for f in ledger.findings() if f["id"] in record["finding_ids"]}
    matching = [s for s in scans if s["scope"] in scopes]
    if scopes != {s["scope"] for s in matching} or any(
        s["status"] != "success" or not s["complete"] for s in matching
    ):
        raise TeateError("applied_source_scan_incomplete")
    for scan in matching:
        checks.append(ledger.ingest(scan))
    if any(
        f["effective_status"] != "resolved"
        for f in ledger.findings()
        if f["id"] in record["finding_ids"]
    ):
        raise TeateError("source_findings_not_verified_resolved")
    return checks


def execute(ledger, policy, state, run_id):
    jobs = Jobs(ledger)
    run = jobs.get(run_id)
    with asset_lock(state, run["asset_id"]):
        return _execute(ledger, policy, state, jobs, run_id)


def _execute(ledger, policy, state, jobs, identifier):
    run = jobs.get(identifier)
    if run["status"] in TERMINAL:
        return compact(run)
    record = run["record"]
    asset = ledger.asset(run["asset_id"])

    def stop(status, reason, *, next_action=None, **updates):
        finding_status = {
            "blocked": "blocked",
            "review": "blocked",
            "uncertain": "blocked",
            "awaiting_ci": "testing",
            "awaiting_deployment": "awaiting_deployment",
            "verification_pending": "awaiting_deployment",
            "rolled_back": "affected",
        }.get(status)
        if finding_status:
            for finding in ledger.findings():
                if finding["id"] in record["finding_ids"] and finding["effective_status"] not in {
                    "resolved",
                    "accepted_risk",
                }:
                    ledger.mark(finding["id"], finding_status, identifier + ": " + reason)
        return compact(
            jobs.update(
                identifier,
                status,
                reason=reason,
                next_action=next_action or NEXT.get(status, NEXT["blocked"]),
                **updates,
            )
        )

    def save(**updates):
        nonlocal run
        run = jobs.update(identifier, run["status"], **updates)

    def steps():
        return {s["name"]: s for s in jobs.get(identifier)["steps"]}

    try:
        if record.get("status") != "candidate_ready":
            return stop(
                "blocked",
                record.get("reason", "candidate_preparation_pending"),
                next_action=(
                    "候補作成が未完了です。理由に示した前提を解決し、"
                    "次のagent cycleで候補を再作成してください。"
                    "同じrunのresumeでは候補を再作成しません"
                ),
            )
        settings = authorize(asset, policy, record)
        candidate = Path(record["worktree"])
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(
            (state / "repairs").resolve()
        ):
            raise TeateError("candidate_path_outside_private_state")
        if source.files(candidate, include_private=True) != record["candidate_files"]:
            return stop("stale" if "deploy" not in steps() else "uncertain", "candidate_changed")
        if set(record["finding_ids"]) - {f["id"] for f in ledger.findings()}:
            return stop("review", "selected_findings_missing")
        for f in ledger.findings():
            if f["id"] in record["finding_ids"] and f["effective_status"] == "accepted_risk":
                return stop("review", "finding_risk_acceptance_changed")
        did_deploy = "deploy" in steps()
        if not did_deploy and settings["mode"] != "github":
            if (
                source.files(Path(asset["path"])) != record["source_files"]
                or source_subject(Path(asset["path"])) != record["original_subject"]
            ):
                return stop("stale", "source_changed_reprepare")
        if not did_deploy and "publish" not in steps():
            if source.files(Path(asset["path"])) != record["source_files"]:
                return stop("stale", "source_changed_reprepare")
            # Retest and rescan immediately before any external write, including
            # adopted legacy candidates. An old successful test is insufficient.
            if datetime.now(UTC) - timestamp(run["created_at"]) > timedelta(hours=24):
                return stop("stale", "candidate_expired_reprepare")
            for package, saved_metadata in record["metadata"].items():
                if repair.registry(package, record["target"]) != saved_metadata:
                    return stop("stale", "registry_metadata_changed_reprepare")
            check = verify(asset, record)
            save(verification=check)
            if check["status"] != "passed":
                return stop("blocked", check.get("reason", "tests_not_passed"))
            baseline = json.loads((candidate.parent / "baseline.json").read_text())
            scans = scan_source({**asset, "path": str(candidate)}, scanner=record["scanner"])
            items = [f for f in ledger.findings() if f["id"] in record["finding_ids"]]
            repair.verified_scans(scans, baseline, items)
            if source.files(candidate, include_private=True) != record["candidate_files"]:
                return stop("stale", "candidate_changed_during_verification")
        required = (
            ("observe", "health", "rollback")
            if settings["mode"] == "github"
            else ("deploy", "observe", "health", "rollback")
        )
        if not settings.get("runtime_assets") or any(not settings.get(name) for name in required):
            return stop(
                "awaiting_deployment",
                "deployment_observation_health_rollback_registration_required",
            )
        for name in required:
            argv, _, _ = hook_spec(settings[name])
            protected = [Path(asset["path"]).resolve(), candidate.resolve(), state.resolve()]
            hook_paths = [
                Path(argv[0]).resolve(),
                *[Path(p).resolve() for p in settings[name].get("files", {})],
            ]
            if any(p.is_relative_to(root) for p in hook_paths for root in protected):
                raise TeateError("deployment_hook_must_be_outside_source_candidate_and_state")
        for asset_id in settings["runtime_assets"]:
            ledger.asset(asset_id)
        if settings["mode"] == "github":
            if "publication" not in run:
                if "publish" in steps():
                    published = publication.reconcile(run, asset)
                    if not published or not published.get("pr"):
                        return stop(
                            "uncertain", "publication_outcome_requires_read_only_reconciliation"
                        )
                else:
                    jobs.intent(identifier, "publish")
                    published = publication.publish(run, asset)
                jobs.finish(identifier, "publish", published)
                save(publication=published)
            result = publication.gate(run["publication"], policy)
            if not result["merged"]:
                if "merge" not in steps():
                    if result["decision"]["action"] != "auto_merge":
                        return stop("awaiting_ci", "; ".join(result["decision"]["reasons"]))
                    from .github import apply_merge

                    jobs.intent(identifier, "merge", {"head_sha": run["publication"]["head_sha"]})
                    response = apply_merge(
                        run["publication"]["repository"],
                        run["publication"]["pr"],
                        result["update"],
                        result["decision"],
                    )
                    jobs.finish(identifier, "merge", response)
                return stop("awaiting_ci", "merge_requested_not_yet_confirmed")
            save(merged=result)
            if "deploy" not in steps():
                # Existing CI/CD performs deployment; never infer it from a merge.
                jobs.intent(identifier, "deploy", {"adapter": "existing_ci_cd"})
        elif "deploy" not in steps():
            jobs.intent(identifier, "deploy", {"candidate_id": digest(record["candidate_files"])})
            response = hook(settings["deploy"], run)
            jobs.finish(identifier, "deploy", response)
            if response.get("status") == "deployed":
                save(deployment=response)
            elif response.get("status") == "failed":
                save(deployment=response, rollback_required=True)
            else:
                return stop("uncertain", "deployment_outcome_unconfirmed")
        observed = hook(
            settings["observe"], run, release_id=run.get("deployment", {}).get("release_id", "")
        )
        if "rollback" in steps():
            previous = run.get("deployment", {}).get("previous_release_id")
            if (
                observed.get("deployment") != "rolled_back"
                or not previous
                or observed.get("release_id") != previous
            ):
                return stop("uncertain", "rollback_outcome_not_verified")
            health = hook(settings["health"], run, release_id=previous)
            if health.get("healthy") is not True or health.get("release_id") != previous:
                return stop("uncertain", "rollback_health_unconfirmed")
            jobs.finish(identifier, "rollback", {"release_id": previous, "verified": True})
            return stop("rolled_back", "previous_release_restored_vulnerabilities_not_resolved")
        if "deployment" not in run:
            if observed.get("deployment") != "applied":
                return stop("verification_pending", "deployment_not_observed_no_mutation_replay")
            if not observed.get("previous_release_id") or not observed.get("release_id"):
                return stop("uncertain", "deployment_and_rollback_identity_missing")
            save(deployment={"status": "deployed", **observed})
            jobs.finish(
                identifier, "deploy", {"release_id": observed["release_id"], "reconciled": True}
            )
        deployment = run["deployment"]
        if not deployment.get("previous_release_id") or not deployment.get("release_id"):
            return stop("uncertain", "deployment_and_rollback_identity_missing")
        identity_ok = (
            observed.get("deployment") == "applied"
            and observed.get("release_id") == deployment["release_id"]
            and observed.get("candidate_id") == digest(record["candidate_files"])
        )
        health = (
            hook(settings["health"], run, release_id=deployment["release_id"])
            if identity_ok
            else {}
        )
        if run.get("rollback_required") or (identity_ok and health.get("healthy") is False):
            jobs.intent(
                identifier, "rollback", {"previous_release_id": deployment["previous_release_id"]}
            )
            save(rollback_required=True)
            response = hook(settings["rollback"], run, release_id=deployment["previous_release_id"])
            jobs.finish(
                identifier,
                "rollback",
                {"status": response.get("status")},
                status="awaiting_observation",
            )
            return stop("uncertain", "rollback_sent_observation_required")
        if (
            not identity_ok
            or health.get("healthy") is not True
            or health.get("release_id") != deployment["release_id"]
        ):
            return stop("verification_pending", "active_release_or_health_unconfirmed")
        results = runtime_verify(ledger, asset, run, observed)
        return stop("verified", "runtime_and_source_rescans_verified", runtime_results=results)
    except (
        TeateError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as exc:
        reason = str(exc) if isinstance(exc, TeateError) else type(exc).__name__
        mutations = steps()
        status = (
            "uncertain"
            if any(s["status"] == "running" for s in mutations.values())
            else "verification_pending"
            if "deploy" in mutations
            else "blocked"
        )
        if reason == "source_or_policy_changed_reprepare":
            status = "uncertain" if mutations else "stale"
        return stop(status, reason)


def cycle(ledger, policy, state, workflow):
    jobs = Jobs(ledger)
    identifiers = [r["id"] for r in jobs.history() if r["status"] not in TERMINAL]
    for decision in workflow["decisions"]:
        for record in decision.get("result", {}).get("results", []):
            run = jobs.create(record["asset_id"], record)
            if (
                run["record"].get("status") != "candidate_ready"
                and record["status"] == "candidate_ready"
                and not run["steps"]
            ):
                jobs.update(run["id"], "stale", reason="superseded_by_verified_candidate")
                run = jobs.create(record["asset_id"], record)
            if run["id"] not in identifiers:
                identifiers.append(run["id"])
    results = []
    for identifier in identifiers:
        try:
            results.append(execute(ledger, policy, state, identifier))
        except TeateError as exc:
            results.append({"id": identifier, "status": "blocked", "reason": str(exc)})
    return results
