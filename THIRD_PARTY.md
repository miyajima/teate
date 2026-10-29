# Third-party tools

Teate itself is MIT. Standard components use permissive licenses; tool binaries
remain external programs. No Vuls, FutureVuls, Renovate, Patchwork or Ansible is
bundled or installed as a standard dependency.

| Component | License | Use |
|---|---|---|
| [OSV-Scanner](https://github.com/google/osv-scanner/blob/main/LICENSE) | Apache-2.0 | dependency scan / in-place repair |
| [Trivy](https://github.com/aquasecurity/trivy/blob/main/LICENSE) | Apache-2.0 | immutable image scan |
| [mise](https://github.com/jdx/mise/blob/main/LICENSE) | MIT | locked tool downloads, checksums, extraction |
| [sandbox-runtime](https://github.com/anthropics/sandbox-runtime/blob/main/LICENSE) | Apache-2.0 | isolated project repair/tests; no model subscription needed |
| feedparser-sgmllib | PSF-2.0 / Python historical notices | feedparser dependency |
| [feedparser](https://github.com/kurtmckee/feedparser/blob/main/LICENSE) | BSD-2-Clause | bounded RSS/Atom byte parsing |
| [GitHub CLI](https://github.com/cli/cli/blob/trunk/LICENSE) | MIT | existing GitHub authentication and gates |
| [Codex CLI](https://github.com/openai/codex/blob/main/LICENSE) | Apache-2.0 | optional ChatGPT-authenticated investigation |
| [Node.js](https://github.com/nodejs/node/blob/main/LICENSE) | MIT + bundled notices | external runtime |
| [npm CLI](https://github.com/npm/cli/blob/latest/LICENSE) | Artistic-2.0 + bundled notices | external dependency fix/install CLI |
| Google Cloud CLI | distribution license/notices | optional external cloud adapter |

`tools/mise.toml` and `tools/mise.lock` pin reviewed official artifact URLs and
checksums for macOS/Linux amd64/arm64. The bootstrap pins mise 2026.10.21 and checks
its official SHA256 manifest. No automatic version/backend upgrades are enabled.
`tools/runtime/package-lock.json`, `tools/codex/package-lock.json` and
`tools/requirements.lock` record transitive package artifacts and hashes. The npm
lockfiles include reported package license identifiers; node-forge uses the BSD-3-Clause option of its dual license; upstream distributions
retain their own LICENSE/NOTICE files in the local installation. Artifact hashes
verify downloads, not subsequent tampering with an installed directory.

Git, Bash, bubblewrap and socat are OS-provided external utilities and may have
GPL/LGPL licenses. They are not vendored or linked into Teate. npm's Artistic-2.0
and Google Cloud CLI's distribution terms are explicit external-tool exceptions;
do not describe either as MIT/Apache. Their use is optional according to the
selected integration. Commercial distribution must retain applicable notices.

The sandbox tool lock explicitly overrides Zod to **4.6.6** for
[CVE-2023-54404 / GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5).
sandbox-runtime 0.0.81 imports the compatible `zod/v3` entrypoint. The actual
sandbox/configuration integration tests cover this combination. Keep the override
until upstream ships an appropriate dependency update.
