# Repository workflow

This is one Python/FastAPI package with independently configured IDP and SP
processes. `plan.md` defines the implementation phases and `docs/phase*.md`
records the completed checkpoints.

## Verification runtime policy

- Run the pytest cases being created or changed, plus cases affected by the
  changed functionality. Select files, node IDs, or `-k` expressions explicitly.
- Do not run the entire `pytest -q` suite by default. A full run needs an explicit
  request or a concrete regression concern that targeted checks cannot cover.
- Share expensive runtime/database fixtures across related scenarios. Use the
  injected `Clock` for expiry checks rather than waiting out real lifetimes.
- Exercise real processes/browser TLS when a networking or browser behavior
  changes; group those checks to minimize service startup/restart overhead.
- Repeat long packaging, deployment, and audit operations only when the change
  requires them. `make check` provides the normal lint/format/type gate.
- Record exact selected commands and observed results. Do not describe a
  targeted run as a full regression run or claim unexecuted checks passed.
