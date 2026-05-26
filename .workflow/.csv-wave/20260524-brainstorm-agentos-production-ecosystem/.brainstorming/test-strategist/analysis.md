# Test Strategist Analysis

## Test Thesis

AgentOS ecosystem work must be gated like a release system, not like an app plugin system. The highest-risk failure is not "install failed"; it is "artifact activated and silently changed the autonomy boundary". Therefore every ecosystem feature needs local-only replay, activation simulation, policy diff, rollback drill and provenance capture.

## Gate Pyramid

### Unit

- manifest parser rejects unknown required fields
- coordinate parser is deterministic
- dependency resolver is stable
- policy merge preserves core invariants
- activation state machine rejects invalid transitions

### Contract

- each artifact kind has schema fixtures
- each activation produces `ActivationReport`
- each failure produces explainable block reason
- optional dependency missing fails before `EffectPrepared`

### Replay

- local registry fixture replay
- policy pack activation replay
- workflow pack activation replay
- test pack replay
- rollback replay
- revocation replay

### Adversarial

- malicious workflow pack tries shell execution
- policy pack tries to disable exact approval
- knowledge pack tries memory poisoning
- model profile tries to embed secret
- adapter pack tries to bypass SecurityExecutionEngine
- registry snapshot references digest mismatch

### Release

- ecosystem replay result hash in provenance
- registry snapshot hash in provenance
- lockfile hash in provenance
- active artifact set hash in support bundle
- QEMU boot smoke still separate

## Compatibility Matrix

Dimensions:

- AgentOS distro version
- `runtime_contracts` schema version
- `agent_core` feature set
- `security_execution` policy version
- CPU architecture
- local-only vs network-enabled
- Firecracker available/unavailable
- host package manager available/unavailable

## Soak And Operations

Long-running Production Distro tests should include:

- boot with active artifact set
- restart `agentd` and recover active set
- rollback activated workflow pack
- revoke artifact and verify block/explain
- rotate registry snapshot
- export support bundle and verify no raw secrets
- offline mode activation from pinned snapshot

## Acceptance Criteria For First Slice

First ecosystem slice is acceptable only if:

- all core schemas are stable JSON and covered by tests
- local fixture registry can install/stage/activate/deactivate without network
- activation goes through SecurityExecutionEngine
- release gate blocks when ecosystem replay is skipped or failed
- support bundle reports active artifact set and hashes
- adversarial fixtures prove no normal shell or policy invariant bypass

## Test Tasks

- `TASK-ECO-040`: Add ecosystem schema unit tests.
- `TASK-ECO-041`: Add local registry replay script.
- `TASK-ECO-042`: Add adversarial artifact pack fixtures.
- `TASK-ECO-043`: Add activation rollback drill.
- `TASK-ECO-044`: Add revocation and advisory replay.
- `TASK-ECO-045`: Add ecosystem hashes to release provenance.
- `TASK-ECO-046`: Add long-running active artifact recovery smoke.
