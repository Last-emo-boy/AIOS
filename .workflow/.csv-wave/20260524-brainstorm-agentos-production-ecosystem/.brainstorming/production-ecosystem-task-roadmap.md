# Production Ecosystem TASK Roadmap

Goal: Move AgentOS from `functional-ready` to a Production Distro with a local-first ecosystem manager and safe extension model.

Working name: `aom`，AgentOS Ecosystem Manager。

## Wave ECO-0: Decisions And Object Model

- `TASK-ECO-000`: Freeze ecosystem scope and `install is not activation` invariant.
- `TASK-ECO-001`: Define `runtime_contracts::ecosystem` module boundary.
- `TASK-ECO-020`: Define artifact coordinate and manifest schema.
- `TASK-ECO-021`: Define registry snapshot and lockfile schema.
- `TASK-ECO-022`: Define activation report and installed/active state schema.
- `TASK-ECO-023`: Define compatibility and migration validation.
- `TASK-ECO-030`: Define trust tier and channel policy.

Exit criteria:

- Manifest, registry snapshot, lockfile and activation report are stable enough for fixtures.
- First artifact kinds are frozen as `policy-pack`, `workflow-pack`, `test-pack`.
- Policy invariants state that policy packs cannot weaken core safety rules.

## Wave ECO-1: Local Registry And Staging

- `TASK-ECO-002`: Add local registry fixture and artifact resolver.
- `TASK-ECO-003`: Implement staging store with digest/signature verification report.
- `TASK-ECO-010`: Define operator-facing artifact explanation format.
- `TASK-ECO-011`: Add `aom` CLI surface for local lifecycle.
- `TASK-ECO-024`: Add revocation/advisory metadata model.
- `TASK-ECO-025`: Add deterministic ecosystem hash projection for provenance.

Exit criteria:

- `aom search/show/verify/stage/explain` works against local fixture registry.
- Staged artifacts are inert and do not change runtime behavior.
- Digest mismatch, revoked artifact and incompatible schema fail closed.

## Wave ECO-2: Activation Through Runtime

- `TASK-ECO-004`: Implement activation planning through AgentCore PlanSpec.
- `TASK-ECO-005`: Route activation side effects through SecurityExecutionEngine.
- `TASK-ECO-006`: Add read-only ecosystem projection in `agentd`.
- `TASK-ECO-012`: Package built-in production-safe policy pack.
- `TASK-ECO-013`: Package built-in service recovery workflow pack.
- `TASK-ECO-014`: Add ecosystem status to TUI/operator projection.

Exit criteria:

- `aom activate` produces a PlanSpec and uses existing approval/policy/effect/audit flow.
- Activation reports include audit range and rollback handle.
- `agentd` shows active/staged/blocked artifacts without owning resolver logic.

## Wave ECO-3: Safety, Replay And Release Gate

- `TASK-ECO-040`: Add ecosystem schema unit tests.
- `TASK-ECO-041`: Add local registry replay script.
- `TASK-ECO-042`: Add adversarial artifact pack fixtures.
- `TASK-ECO-043`: Add activation rollback drill.
- `TASK-ECO-044`: Add revocation and advisory replay.
- `TASK-ECO-045`: Add ecosystem hashes to release provenance.
- `TASK-ECO-046`: Add long-running active artifact recovery smoke.

Exit criteria:

- Release gate blocks when ecosystem replay is skipped or failed.
- Provenance records registry snapshot hash, lockfile hash and replay evidence hash.
- Adversarial fixtures cover shell bypass, policy weakening, memory poisoning, secret embedding and adapter bypass.

## Wave ECO-4: Trust And Organization Controls

- `TASK-ECO-015`: Define verified/community/local-dev channel policy.
- `TASK-ECO-031`: Define signing and revocation requirements.
- `TASK-ECO-032`: Define no-maintainer-script activation rule.
- `TASK-ECO-033`: Define community artifact sandbox-only policy.
- `TASK-ECO-034`: Add ecosystem state to support bundle manifest.
- `TASK-ECO-035`: Define organization allowlist and denylist overlay.

Exit criteria:

- Production Distro can pin allowed channels and reject unsigned artifacts.
- Support bundle explains active artifact set, trust tier, channel and hashes without raw secrets.
- Community/local-dev artifacts cannot be production-promoted by default.

## Wave ECO-5: Model, Knowledge, Adapter And Image Packs

- `TASK-ECO-050`: Define model profile pack schema and local/stub/remote optionality.
- `TASK-ECO-051`: Define knowledge pack schema with trust labels and memory quarantine.
- `TASK-ECO-052`: Add model/knowledge adversarial replay fixtures.
- `TASK-ECO-060`: Define runtime adapter pack schema.
- `TASK-ECO-061`: Define execution image pack schema for Firecracker/sandbox/update bundles.
- `TASK-ECO-062`: Add adapter/image optional dependency fail-closed replay.

Exit criteria:

- Model and knowledge packs cannot leak secrets or poison privileged memory.
- Adapter packs cannot bypass SecurityExecutionEngine.
- Image packs prove provenance, compatibility and rollback rules before activation.

## Recommended Next Implementation Slice

Start with Wave ECO-0 and ECO-1 only. They create the ecosystem spine while keeping Production Distro risk controlled:

1. `runtime_contracts::ecosystem`
2. local registry fixture
3. manifest/lockfile/activation report schema
4. `aom show/verify/stage/explain`
5. deterministic provenance hashes

Then implement activation in Wave ECO-2 once schemas and staging are stable.
