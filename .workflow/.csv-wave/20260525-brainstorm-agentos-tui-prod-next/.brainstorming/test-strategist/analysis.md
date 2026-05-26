# Test Strategist Analysis

## Verification Direction

The next cadence should preserve the current release gates while adding UI-specific determinism gates. Full-screen TUI work must not make scripted mode brittle.

## Required Gates

- `cargo fmt --check`
- `cargo test --workspace`
- `cargo test -p agentd tui --no-fail-fast`
- `scripts/tui-replay.ps1`
- `scripts/production-runbook-smoke.ps1`
- `scripts/ecosystem-replay.ps1`
- `scripts/build-release.ps1`
- QEMU boot smoke with TUI marker

## New Test Classes

### Layout Snapshots

Golden snapshots for:

- wide dashboard
- narrow terminal fallback
- command palette
- approval center
- recovery workbench
- support console
- ecosystem artifact detail

Snapshots must be line-oriented and deterministic.

### Event Model Tests

Prove:

- refresh does not mutate durable state
- event cursor resumes after restart
- projection source hashes change only when source changes
- transient errors do not overwrite run state

### Adversarial UX Tests

Extend existing fixtures:

- command alias injection
- keyboard shortcut bypass
- stale approval focus reuse
- hidden shell fragments in command palette input
- secret-like text in history and session profile

### Soak Tests

Local-only long-running scripted run:

- repeated refresh
- multiple runs
- approval expiry
- recovery after interrupted command
- support bundle export
- AOM preview

### Release Evidence Tests

Release provenance should include:

- TUI layout snapshot hash
- TUI replay status
- runbook TUI case status
- QEMU TUI marker
- operator command registry hash
- TUI config hash

## Promotion Criteria

Do not promote to next milestone unless:

- all current gates remain green
- full-screen shell has deterministic scripted parity
- high-risk commands cannot bypass preview
- approval/recovery views remain exact and redacted
- QEMU still proves boot marker and runtime manifest marker

## Recommendation

Add test scaffolding in the same wave as full-screen shell. UI work without snapshot/replay gates will create regressions quickly.
