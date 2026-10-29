"""Read-only collection and scanner adapters. Never install project dependencies."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from .model import TeateError, digest, image_digest, snapshot, utcnow

LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.lock",
    "Gemfile.lock",
    "go.sum",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "composer.lock",
    "packages.lock.json",
    "requirements.txt",
}
SKIP = {".git", "node_modules", ".venv", "venv", "target", ".teate", "vendor", "dist"}


def run(
    args: list[str], *, cwd: Path | None = None, timeout: int = 180
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            args,
            check=False,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=timeout,
            env={**os.environ, "HOMEBREW_NO_AUTO_UPDATE": "1", "CI": "true"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TeateError(f"{Path(args[0]).name}: {type(exc).__name__}") from exc


def discover(root: Path) -> list[dict]:
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise TeateError(f"Missing discovery directory: {root}")
    projects = []
    for path in sorted(root.iterdir()):
        if path.name.startswith(".") or path.is_symlink() or not path.is_dir():
            continue
        if (path / ".git").exists() or any((path / name).exists() for name in LOCKFILES):
            repository = ""
            ref = (
                run(["git", "-C", str(path), "remote", "get-url", "origin"])
                if shutil.which("git") and (path / ".git").exists()
                else subprocess.CompletedProcess([], 1, "", "")
            )
            if ref.returncode == 0:
                # Drop any embedded URL credentials before putting a remote in the inventory.
                import urllib.parse

                value = ref.stdout.strip()
                parsed = urllib.parse.urlsplit(value)
                if parsed.scheme in {"http", "https"}:
                    repository = urllib.parse.urlunsplit(
                        (parsed.scheme, parsed.hostname or "", parsed.path, "", "")
                    )
                elif value.startswith("git@github.com:"):
                    repository = "https://github.com/" + value.removeprefix("git@github.com:")
            projects.append(
                {
                    "id": f"source:{platform.node()}:{path.name}",
                    "project": path.name,
                    "environment": "development",
                    "kind": "source",
                    "path": str(path),
                    "repository": repository,
                    "exposure": "unknown",
                }
            )
    return projects


def lockfiles(root: Path) -> list[str]:
    result = []
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [
            d for d in directories if d not in SKIP and not (Path(current) / d).is_symlink()
        ]
        for name in files:
            path = Path(current) / name
            if name in LOCKFILES and not path.is_symlink():
                result.append(str(path.relative_to(root)))
    return sorted(result)


def source_subject(root: Path) -> dict:
    sha = (
        run(["git", "-C", str(root), "rev-parse", "HEAD"])
        if shutil.which("git") and (root / ".git").exists()
        else subprocess.CompletedProcess([], 1, "", "")
    )
    # Uncommitted lockfile changes must have their own identity too.
    locks = lockfiles(root)
    hashes = {p: digest((root / p).read_text(errors="replace")) for p in locks}
    return {
        "type": "source",
        "revision": sha.stdout.strip() if sha.returncode == 0 else "unversioned",
        "host_id": platform.node(),
        "lockfile_hashes": hashes,
        "lockfile_digest": digest(hashes),
    }


def osv_findings(raw: dict, root: Path | None = None) -> list[dict]:
    if not isinstance(raw.get("results"), list):
        raise TeateError("OSV output is missing the results array")
    findings = []
    for result in raw["results"]:
        source = result.get("source", {})
        location = source.get("path", "unknown")
        if root and Path(location).is_absolute():
            try:
                location = str(Path(location).relative_to(root))
            except ValueError:
                pass
        for item in result.get("packages", []):
            package = item.get("package", {})
            for vuln in item.get("vulnerabilities", []):
                affected = [
                    a
                    for a in vuln.get("affected", [])
                    if a.get("package", {}).get("name", package.get("name")) == package.get("name")
                ]
                fixes = sorted(
                    {
                        event["fixed"]
                        for a in affected
                        for r in a.get("ranges", [])
                        for event in r.get("events", [])
                        if event.get("fixed")
                    }
                )
                severity = vuln.get("database_specific", {}).get("severity", "UNKNOWN").upper()
                if severity == "MODERATE":
                    severity = "MEDIUM"
                findings.append(
                    {
                        "advisory_id": vuln["id"],
                        "aliases": vuln.get("aliases", []),
                        "package": package["name"],
                        "ecosystem": package["ecosystem"],
                        "version": package.get("version", "unknown"),
                        "location": location,
                        "fixed_versions": fixes,
                        "severity": severity,
                        "malicious": vuln["id"].startswith("MAL-"),
                        "summary": vuln.get("summary", ""),
                        "url": "https://osv.dev/vulnerability/" + vuln["id"],
                    }
                )
    return findings


def trivy_findings(raw: dict) -> list[dict]:
    if raw.get("SchemaVersion") != 2 or "ArtifactName" not in raw:
        raise TeateError("Unsupported or incomplete Trivy JSON")
    findings = []
    for result in raw.get("Results", []):
        ecosystem = result.get("Type", result.get("Class", "unknown"))
        for vuln in result.get("Vulnerabilities", []):
            findings.append(
                {
                    "advisory_id": vuln["VulnerabilityID"],
                    "aliases": [],
                    "package": vuln["PkgName"],
                    "ecosystem": ecosystem,
                    "version": vuln["InstalledVersion"],
                    "location": vuln.get("PkgPath", result.get("Target", "image")),
                    "fixed_versions": [
                        v.strip() for v in vuln.get("FixedVersion", "").split(",") if v.strip()
                    ],
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "summary": vuln.get("Title", ""),
                    "url": vuln.get("PrimaryURL", ""),
                }
            )
    return findings


def npm_findings(raw: dict, location: str) -> list[dict]:
    if raw.get("auditReportVersion") != 2 or not isinstance(raw.get("vulnerabilities"), dict):
        raise TeateError("Unsupported npm audit JSON; expected auditReportVersion 2")
    findings = []
    for name, item in raw["vulnerabilities"].items():
        for advisory in item.get("via", []):
            if not isinstance(advisory, dict):
                continue  # The advisory is represented on its actual vulnerable dependency.
            url = advisory.get("url", "")
            advisory_id = (
                url.rstrip("/").split("/")[-1] if "GHSA-" in url else f"npm:{advisory['source']}"
            )
            fix = item.get("fixAvailable")
            fixes = (
                [fix["version"]]
                if isinstance(fix, dict) and fix.get("name") == name and fix.get("version")
                else []
            )
            findings.append(
                {
                    "advisory_id": advisory_id,
                    "aliases": [],
                    "package": name,
                    "ecosystem": "npm",
                    "version": item.get("installedVersion", "unknown"),
                    "affected_range": advisory.get("range", item.get("range", "")),
                    "location": location,
                    "fixed_versions": fixes,
                    "severity": advisory.get("severity", "unknown")
                    .upper()
                    .replace("MODERATE", "MEDIUM"),
                    "malicious": advisory.get("title", "").lower().startswith("malicious code in "),
                    "summary": advisory.get("title", ""),
                    "url": url,
                }
            )
    return findings


def scan_source(asset: dict, *, scanner: str = "osv") -> list[dict]:
    if asset.get("host_id") and asset["host_id"] != platform.node():
        return [
            snapshot(
                asset["id"],
                scanner,
                "repository",
                {},
                status="error",
                complete=False,
                message="asset belongs to another or unverified host",
            )
        ]
    root = Path(asset["path"]).expanduser().resolve()
    if not root.is_dir():
        return [
            snapshot(
                asset["id"],
                scanner,
                "repository",
                {},
                status="error",
                complete=False,
                message="project directory unavailable",
            )
        ]
    subject = source_subject(root)
    locks = lockfiles(root)
    if scanner == "osv":
        if not shutil.which("osv-scanner"):
            return [
                snapshot(
                    asset["id"],
                    scanner,
                    "repository",
                    subject,
                    status="unsupported",
                    complete=False,
                    message="osv-scanner not installed",
                )
            ]
        if not locks:
            return [
                snapshot(
                    asset["id"],
                    scanner,
                    "repository",
                    subject,
                    status="unsupported",
                    complete=False,
                    message="no supported dependency manifest found",
                )
            ]
        try:
            # Use central policy rather than project-local suppressions. Reachability
            # analysis and dependency resolution can execute project build scripts.
            with tempfile.TemporaryDirectory(prefix="teate-osv-") as temporary:
                scanner_config = Path(temporary) / "osv-scanner.toml"
                scanner_config.write_text("# Central Teate scan; no local suppressions\n")
                command = [
                    "osv-scanner",
                    "scan",
                    "source",
                    "--format=json",
                    "--no-call-analysis=all",
                    "--no-resolve",
                    f"--config={scanner_config}",
                    *[f"--lockfile={root / p}" for p in locks],
                ]
                result = run(command, cwd=root, timeout=600)
            if result.returncode not in (0, 1):
                if "api.osv.dev" in result.stderr and "Forbidden" in result.stderr:
                    raise TeateError("OSV API access denied by network policy: api.osv.dev")
                raise TeateError(
                    f"osv-scanner exited {result.returncode}; check scanner/network availability"
                )
            raw = json.loads(result.stdout)
            findings = osv_findings(raw, root)
            # Some OSV versions put unsuccessful package queries in the JSON output.
            complete = not bool(raw.get("errors"))
            return [
                snapshot(
                    asset["id"],
                    scanner,
                    "repository",
                    subject,
                    findings,
                    complete=complete,
                    message="partial OSV errors" if not complete else "",
                )
            ]
        except (TeateError, ValueError, KeyError, TypeError) as exc:
            return [
                snapshot(
                    asset["id"],
                    scanner,
                    "repository",
                    subject,
                    status="error",
                    complete=False,
                    message=str(exc),
                )
            ]
    if scanner != "npm-audit":
        raise TeateError("Source scanner must be osv or npm-audit")
    snapshots = []
    for lock in locks:
        if Path(lock).name not in {"package-lock.json", "npm-shrinkwrap.json"}:
            snapshots.append(
                snapshot(
                    asset["id"],
                    scanner,
                    lock,
                    subject,
                    status="unsupported",
                    complete=False,
                    message="this manifest requires OSV-Scanner",
                )
            )
            continue
        try:
            # npm audit is read-only; --ignore-scripts prevents project lifecycle hooks.
            with tempfile.TemporaryDirectory(prefix="teate-npm-audit-") as temporary:
                directory = Path(temporary)
                shutil.copy2(root / lock, directory / Path(lock).name)
                manifest = (root / lock).parent / "package.json"
                if manifest.is_file() and not manifest.is_symlink():
                    shutil.copy2(manifest, directory / "package.json")
                (directory / "user.npmrc").write_text("")
                (directory / "global.npmrc").write_text("")
                result = run(
                    [
                        "npm",
                        "audit",
                        "--package-lock-only",
                        "--ignore-scripts",
                        "--json",
                        "--include=dev",
                        "--include=optional",
                        "--include=peer",
                        "--registry=https://registry.npmjs.org",
                        "--cache=" + str(directory / "cache"),
                        "--userconfig=" + str(directory / "user.npmrc"),
                        "--globalconfig=" + str(directory / "global.npmrc"),
                    ],
                    cwd=directory,
                    timeout=180,
                )
            if result.returncode not in (0, 1):
                raise TeateError(f"npm audit exited {result.returncode}; check registry access")
            raw = json.loads(result.stdout)
            if raw.get("error"):
                raise TeateError("npm audit returned a registry error")
            findings = npm_findings(raw, lock)
            installed = json.loads((root / lock).read_text()).get("packages", {})
            for f in findings:
                versions = sorted(
                    {
                        v["version"]
                        for p, v in installed.items()
                        if p.endswith("node_modules/" + f["package"]) and v.get("version")
                    }
                )
                if versions:
                    f["version"] = ", ".join(versions)
            snapshots.append(snapshot(asset["id"], scanner, lock, subject, findings))
        except (TeateError, ValueError, KeyError, TypeError) as exc:
            snapshots.append(
                snapshot(
                    asset["id"],
                    scanner,
                    lock,
                    subject,
                    status="error",
                    complete=False,
                    message=str(exc),
                )
            )
    if not locks:
        snapshots.append(
            snapshot(
                asset["id"],
                scanner,
                "repository",
                subject,
                status="unsupported",
                complete=False,
                message="no supported dependency manifest found",
            )
        )
    return snapshots


def scan_image(asset: dict, image: str | None = None) -> dict:
    reference = image or asset.get("image", "")
    subject = {"type": "image", "digest": image_digest(reference), "reference": reference}
    if not image_digest(reference):
        return snapshot(
            asset["id"],
            "trivy",
            "image",
            subject,
            status="error",
            complete=False,
            message="a sha256-pinned image is required",
        )
    try:
        result = run(
            ["trivy", "image", "--scanners", "vuln", "--format", "json", "--quiet", reference],
            timeout=600,
        )
        if result.returncode != 0:
            raise TeateError(f"Trivy exited {result.returncode}; check registry/database access")
        raw = json.loads(result.stdout)
        actual = raw.get("Metadata", {}).get("RepoDigests", [])
        if image_digest(reference) not in {image_digest(x) for x in actual}:
            raise TeateError("Trivy output does not attest to the requested digest")
        return snapshot(asset["id"], "trivy", "image", subject, trivy_findings(raw))
    except (TeateError, ValueError, KeyError, TypeError) as exc:
        return snapshot(
            asset["id"], "trivy", "image", subject, status="error", complete=False, message=str(exc)
        )


def collect_mac(asset: dict) -> tuple[dict, dict]:
    observed = utcnow()
    if platform.system() != "Darwin" or asset.get("host_id") != platform.node():
        observation = {
            "observed_at": observed,
            "status": "error",
            "message": "configured Mac is not this host",
        }
        return observation, snapshot(
            asset["id"],
            "mac-inventory",
            "host",
            {},
            status="error",
            complete=False,
            message=observation["message"],
            observed_at=observed,
        )
    inventory = {
        "observed_at": observed,
        "status": "success",
        "host_id": platform.node(),
        "architecture": platform.machine(),
        "macos": platform.mac_ver()[0],
        "formulae": [],
    }
    try:
        if shutil.which("brew"):
            info = run(["brew", "info", "--json=v2", "--installed"])
            if info.returncode != 0:
                raise TeateError("Homebrew inventory failed")
            raw = json.loads(info.stdout)
            inventory["formulae"] = [
                {"name": f["name"], "versions": [v["version"] for v in f.get("installed", [])]}
                for f in raw.get("formulae", [])
            ]
            inventory["casks"] = [
                {"name": c["token"], "version": c.get("installed")} for c in raw.get("casks", [])
            ]
        else:
            inventory["homebrew_status"] = "not installed"
    except (TeateError, ValueError, KeyError) as exc:
        inventory.update(status="error", message=str(exc))
    # Inventory is useful evidence, but it is not a macOS CVE scan.
    return inventory, snapshot(
        asset["id"],
        "mac-inventory",
        "host",
        {"type": "host", "host_id": platform.node()},
        status="unsupported",
        complete=False,
        message="inventory collected; macOS/browser CVE assessment requires vendor advisory correlation",
        observed_at=observed,
    )


def collect_cloud_run(asset: dict) -> dict:
    observed = utcnow()
    try:
        common = ["--project", asset["gcp_project"], "--region", asset["region"], "--format=json"]
        result = run(["gcloud", "run", "services", "describe", asset["service"], *common])
        if result.returncode != 0:
            raise TeateError("Cloud Run service read failed; check identity and permissions")
        service = json.loads(result.stdout)
        traffic = service.get("status", {}).get("traffic", [])
        revisions = sorted(
            {
                t["revisionName"]
                for t in traffic
                if t.get("revisionName") and (t.get("percent", 0) > 0 or t.get("tag"))
            }
        )
        if not revisions:
            raise TeateError("No verified routable revisions in Cloud Run status")
        images, references = set(), set()
        for name in revisions:
            response = run(["gcloud", "run", "revisions", "describe", name, *common])
            if response.returncode != 0:
                raise TeateError("Cloud Run revision read failed")
            revision = json.loads(response.stdout)
            status = revision.get("status", {})
            if not any(
                c.get("type") == "Ready" and str(c.get("status")).lower() == "true"
                for c in status.get("conditions", [])
            ):
                raise TeateError("A routable revision is not Ready")
            refs = [c.get("imageDigest", "") for c in status.get("containerStatuses", [])]
            if not refs:
                refs = [status.get("imageDigest", "")]
            if not refs or any(not image_digest(ref) or "@" not in ref for ref in refs):
                raise TeateError("Cloud Run did not return all immutable image references")
            images.update(image_digest(ref) for ref in refs)
            references.update(refs)
        return {
            "observed_at": observed,
            "status": "success",
            "revisions": revisions,
            "images": sorted(images),
            "image_refs": sorted(references),
        }
    except (TeateError, KeyError, ValueError, TypeError) as exc:
        return {"observed_at": observed, "status": "error", "message": str(exc)}


def scan_cloud_run(asset: dict, observation: dict) -> dict:
    subject = {
        "type": "runtime",
        "digests": observation.get("images", []),
        "revisions": observation.get("revisions", []),
    }
    if observation.get("status") != "success":
        return snapshot(
            asset["id"],
            "trivy",
            "runtime",
            subject,
            status="error",
            complete=False,
            message=observation.get("message", "runtime identity unavailable"),
        )
    reports = [scan_image(asset, ref) for ref in observation["image_refs"]]
    valid = bool(reports) and all(r["status"] == "success" and r["complete"] for r in reports)
    combined = {}
    for report in reports:
        for finding in report["findings"]:
            key = (
                finding["advisory_id"],
                finding["package"],
                finding["ecosystem"],
                finding.get("location", ""),
            )
            if key not in combined:
                combined[key] = {**finding, "affected_versions": [], "affected_images": []}
            item = combined[key]
            item["affected_versions"] = sorted({*item["affected_versions"], finding["version"]})
            item["affected_images"] = sorted(
                {*item["affected_images"], report["subject"]["digest"]}
            )
            item["version"] = ", ".join(item["affected_versions"])
    return snapshot(
        asset["id"],
        "trivy",
        "runtime",
        subject,
        list(combined.values()),
        status="success" if valid else "error",
        complete=valid,
        message="; ".join(r["message"] for r in reports if r["message"]),
    )
