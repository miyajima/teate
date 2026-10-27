# Contributing

Python 3.11 or newer and Git are required. No Python runtime dependencies are
needed. Scanner integrations use separately installed tools; unit tests use
synthetic data and do not need cloud credentials, npm registry access or an LLM.

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q teate scripts
```

Run `ruff check teate tests scripts` when Ruff is available. Keep safety decisions
deterministic. Changes to collectors and transports need tests for partial,
failed, stale and mismatched evidence. Model output must never authorize commands,
change policy or mark findings resolved.

Use fictional asset names, paths and credentials in examples and tests. Never
attach a real ledger, receipt, log, authentication file or private configuration
to an issue or pull request. Read [SECURITY.md](SECURITY.md) before reporting a
security issue. Contributions are licensed under [MIT](LICENSE).
