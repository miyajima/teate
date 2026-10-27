#!/usr/bin/env python3
"""Explicit repo allowlist for a self-hosted Renovate job."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from teate.config import load_config
from teate.github import repository_name

config = load_config("config/ci.json")
repositories = sorted(
    {
        repository_name(a["repository"])
        for a in config["assets"]
        if a["kind"] == "source" and a.get("repository") and not a.get("host_id")
    }
)
Path(".teate").mkdir(exist_ok=True)
Path(".teate/renovate.json").write_text(
    json.dumps(
        {
            "platform": "github",
            "autodiscover": False,
            "repositories": repositories,
            "allowScripts": False,
            "onboarding": True,
            "requireConfig": "required",
            "automerge": False,
            "onboardingConfig": {
                "extends": ["config:best-practices"],
                "automerge": False,
                "minimumReleaseAge": "14 days",
                "dependencyDashboard": True,
                "vulnerabilityAlerts": {"enabled": True, "minimumReleaseAge": "0 days"},
            },
        },
        indent=2,
    )
    + "\n"
)
