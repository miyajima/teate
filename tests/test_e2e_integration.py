"""Network-backed, opt-in disposable npm repair through actual deployment hooks."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from teate.collect import scan_source
from teate.execution import execute
from teate.jobs import Jobs
from teate.repair import prepare
from teate.store import Ledger


@unittest.skipUnless(
    os.environ.get("TEATE_SANDBOX_INTEGRATION") == "1", "opt-in disposable npm end-to-end"
)
class NpmEndToEndTests(unittest.TestCase):
    def test_plain_and_git_source_repair_deploy_and_runtime_verify(self):
        for with_git in (False, True):
            with self.subTest(git=with_git), tempfile.TemporaryDirectory() as temporary:
                self.run_case(Path(temporary).resolve(), with_git)

    def run_case(self, root, with_git):
        from teate.sandbox import execute as sandbox

        candidate_probe = root / "probe"
        candidate_probe.mkdir()
        probe = sandbox(candidate_probe, ["node", "-e", 'console.log("ready")'], timeout=15)
        if probe["status"] == "blocked":
            self.skipTest("OS sandbox unavailable: " + probe.get("reason", "unknown"))
        self.assertEqual(probe["status"], "passed", probe)
        app, runtime = root / "app", root / "runtime"
        app.mkdir()
        runtime.mkdir()
        (app / "package.json").write_text(
            json.dumps(
                {
                    "name": "teate-disposable-test",
                    "version": "1.0.0",
                    "private": True,
                    "dependencies": {"source-map-js": "^1.2.1"},
                }
            )
        )
        (app / "test.js").write_text("""const assert = require('node:assert/strict');
const {SourceMapGenerator} = require('source-map-js');
const map = new SourceMapGenerator({file: 'out.js'});
map.addMapping({generated: {line: 1, column: 0}, source: 'in.js', original: {line: 1, column: 0}});
assert.deepEqual(JSON.parse(map.toString()).sources, ['in.js']);
""")
        user, global_ = root / "user.npmrc", root / "global.npmrc"
        user.write_text("")
        global_.write_text("")
        subprocess.run(
            [
                "npm",
                "install",
                "source-map-js@1.2.1",
                "--save-prefix=^",
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--cache=" + str(root / "cache"),
                "--registry=https://registry.npmjs.org",
                "--userconfig=" + str(user),
                "--globalconfig=" + str(global_),
            ],
            cwd=app,
            check=True,
            timeout=120,
            capture_output=True,
        )
        if with_git:
            for args in (
                ["init", "-q"],
                ["add", "."],
                [
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-qm",
                    "initial",
                ],
            ):
                subprocess.run(
                    ["git", "-c", "core.hooksPath=/dev/null", "-C", str(app), *args],
                    check=True,
                    capture_output=True,
                )
        script = root / "operator.py"
        script.write_text("""import json,pathlib,shutil,sys
mode, run_id, candidate_id, candidate, app, runtime, state = sys.argv[1:]
state=pathlib.Path(state)
if mode == 'deploy':
 for destination in (app,runtime):
  for name in ('package.json','package-lock.json','test.js'):
   shutil.copy2(pathlib.Path(candidate)/name,pathlib.Path(destination)/name)
 result={'status':'deployed','run_id':run_id,'candidate_id':candidate_id,'release_id':'release-new','previous_release_id':'release-old'}
 state.write_text(json.dumps(result))
elif mode == 'observe':
 result={**json.loads(state.read_text()),'status':'success','deployment':'applied'}
elif mode == 'health':
 result={'run_id':run_id,'release_id':'release-new','healthy':True}
else:
 result={'run_id':run_id,'status':'rolled_back','release_id':'release-old'}
print(json.dumps(result))
""")
        executable = Path(sys.executable).resolve()
        settings = {"enabled": True, "mode": "local", "runtime_assets": ["runtime"]}
        for mode in ("deploy", "observe", "health", "rollback"):
            settings[mode] = {
                "argv": [
                    str(executable),
                    str(script),
                    mode,
                    "{run_id}",
                    "{candidate_id}",
                    "{candidate}",
                    str(app),
                    str(runtime),
                    str(root / "release.json"),
                ],
                "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                "files": {str(script): hashlib.sha256(script.read_bytes()).hexdigest()},
            }
        asset = {
            "id": "app",
            "project": "demo",
            "kind": "source",
            "environment": "test",
            "path": str(app),
            "verification": {
                "install_dependencies": True,
                "commands": [{"argv": ["node", "test.js"]}],
            },
            "remediation": settings,
        }
        policy = {
            "automation": {
                "enabled": True,
                "allowed_packages": ["source-map-js"],
                "minimum_release_age_hours": 0,
            }
        }
        with_ledger = Ledger(root / "state/ledger.sqlite3")
        try:
            with_ledger.register(
                [
                    asset,
                    {
                        **asset,
                        "id": "runtime",
                        "path": str(runtime),
                        "environment": "production",
                        "remediation": {},
                    },
                ]
            )
            for scan in scan_source(asset, scanner="npm-audit"):
                with_ledger.ingest(scan)
            findings = [f for f in with_ledger.findings() if f["package"] == "source-map-js"]
            self.assertTrue(
                findings,
                "Official audit no longer reports the pinned fixture; replace the fixture explicitly",
            )
            result = prepare(
                with_ledger, policy, root / "state", [f["id"] for f in findings], "1.2.2"
            )
            record = result["results"][0]
            self.assertEqual(record["status"], "candidate_ready", record)
            run = Jobs(with_ledger).create("app", record)
            outcome = execute(with_ledger, policy, root / "state", run["id"])
            self.assertEqual(outcome["status"], "verified", outcome)
            self.assertEqual(
                execute(with_ledger, policy, root / "state", run["id"])["status"], "verified"
            )
            self.assertTrue(
                all(f["effective_status"] == "resolved" for f in with_ledger.findings())
            )
        finally:
            with_ledger.close()
