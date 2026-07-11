# codescan — Change and Release Procedure

The documented change process for this repository: how a change is made,
gated, approved, released, and — when needed — expedited. Governance context
in [GOVERNANCE.md](GOVERNANCE.md) §3–§4.

## Change flow (every change)

1. **Branch per change** off `main` (`feat/...`, `fix/...`, `docs/...`).
2. **Full local gate** before commit — all three must pass clean:
   ```bash
   ruff check src tests
   mypy                      # clean gate; the package ships py.typed
   pytest -q                 # offline, deterministic, no API keys
   ```
3. **Docs in lockstep.** A behavior change updates, in the same commit:
   `README.md`, `docs/DESIGN.md`, `docs/DESIGN.docx` (regenerate via
   `node docs/build_docx.mjs` — it embeds its own prose; mirror edits there),
   `config/config.example.yaml` for new settings, and the web Config tab for
   new toggles. Diagram changes edit `docs/architecture.svg` **and**
   `docs/make_diagram.py`, then regenerate the PNG (`python docs/make_diagram.py`).
   New tests accompany every feature.
4. **UI changes are verified in a browser** against the running dev server
   before commit, not just by tests.
5. **Merge**: fast-forward only (`git merge --ff-only`), delete the branch,
   push. History stays linear; every commit on `main` passed the full gate.
6. **CI re-runs the gate** on every push/PR ([ci.yml](../.github/workflows/ci.yml)):
   ruff + mypy + pytest on a Python 3.10–3.12 matrix, a Docker image build, and a
   **supply-chain job** — a `pip-audit` dependency vulnerability scan and a
   CycloneDX SBOM uploaded as a build artifact. A failing CI run on `main` blocks
   further merges until it is fixed.

**Never committed:** runtime artifacts (`audit.jsonl`, `validation_state.json`,
`servicenow_import.json`, `threat_models.json`, `config.overrides.json`,
`state.db`) — all gitignored; secrets live in the environment or Vault only.

## Approval model

- **Current (single-maintainer):** the maintainer is the change authority; the
  CI gate is the enforced technical control; the git log (with descriptive,
  per-change commit messages) is the change record.
- **Required hardening for multi-maintainer / production operation:** enable
  branch protection on `main` (require the CI check + at least one review,
  forbid force-push), add `CODEOWNERS` for `src/codescan/` and `config/`, and
  route deploy approvals through a protected environment. The procedure above
  already assumes reviewable, single-purpose commits, so this is a settings
  change, not a workflow change.

## Releases

1. Bump `version` in `pyproject.toml` (semver: breaking / feature / fix).
2. Update release notes (changelog section or GitHub release body) from the
   commit log since the last tag.
3. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. Build and publish the container from the tagged commit (the same
   `Dockerfile` CI builds); deploy `docker-compose.prod.yml` environments from
   tags, never from `main` directly.
5. **Patching cadence:** dependency updates go through the identical change
   flow — the offline test suite makes security patching low-risk to verify.

## Emergency changes

Same gate, expedited process: branch, fix, full local gate (never skipped —
it runs in minutes offline), ff-merge, push, and record the rationale in the
commit message body (`Emergency: <what broke, why this is safe>`). If review
is bypassed under the multi-maintainer model, open a retroactive review issue
within one business day. The git log plus CI run is the emergency-change
record.

## Runtime configuration changes (no code)

Operators change scoring weights, model routing, enrichment toggles, and
feature flags from the **Config tab** (or `POST /api/config`). These are
validated server-side, persisted to `config.overrides.json` (the system of
record, layered over base config on restart), and **audited** as
`config.changed` events naming the actor and every changed key — forwarded to
the SIEM sinks like all audit events. Secrets are never editable through this
path; they stay in the environment/Vault.
