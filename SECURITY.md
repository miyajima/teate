# Security policy

Teate is early-stage software. No release has received an independent security
audit. A successful scan or prepared patch is not proof that an environment is
safe; unsupported, failed and stale checks remain unknown.

## Reporting vulnerabilities in Teate

When enabled, use [GitHub private vulnerability reporting](https://github.com/miyajima/teate/security/advisories/new)
for vulnerabilities in Teate itself. If the reporting form is unavailable, open
an issue requesting a private contact channel without including technical
details, affected systems or operational data. Include the version or commit, a minimal
reproduction using synthetic data, impact and suggested remediation if available.
Do not include credentials, live infrastructure names, customer data or private
scan receipts. Do not open a public issue with exploit details or sensitive data.
Only the current development version is maintained; response times are not
guaranteed.

## Keep operational data private

The public repository distributes source code and example configuration. Keep
inventories, SQLite ledgers, receipts, remediation worktrees, logs and reports
on your own machine or in a separate private operations repository. A branch
inside a public repository is public too. Public Actions artifacts, job summaries
and issue bodies can also disclose operational data.

Operational workflows require both a private repository and the explicit
`TEATE_OPERATIONS_ENABLED=true` repository variable. GitHub evidence publication,
issue writes and state transport also verify that the destination is private.
Package auto-merge and Mac updates still require their own explicit allowlists,
checks and permissions. Public project repositories may remain remediation
targets; the central evidence store must be private.

Do not commit `.teate/`, `config/local.json`, authentication files, private keys
or environment files. Ignore rules are an extra precaution, not a substitute
for inspecting the files and Git history you publish. Do not upload local Git
bundles or state archives: they can contain private historical configuration.

Codex support uses the CLI's existing ChatGPT authentication, without copying
credentials or falling back to an API key. Treat configured project commands,
tokens and scanner output as untrusted. Preserve the existing proxy, CA trust
and network policy.
