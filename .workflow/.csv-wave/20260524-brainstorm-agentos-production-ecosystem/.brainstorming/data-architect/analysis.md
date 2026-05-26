# Data Architect Analysis

## Data Thesis

The ecosystem succeeds or fails on stable identity, graph resolution and evidence. AgentOS artifacts need content-addressed integrity, human-readable coordinates, compatibility constraints and activation evidence. Traditional package metadata is not enough because AgentOS artifacts alter autonomy, policy and execution boundaries.

## Artifact Coordinate

Recommended coordinate:

```text
agentos:<kind>/<publisher>/<name>@<version>
```

Examples:

```text
agentos:policy/core/production-safe@0.1.0
agentos:workflow/core/service-recovery@0.1.0
agentos:test/core/ecosystem-replay@0.1.0
agentos:adapter/core/debian-package-manager@0.1.0
agentos:image/core/firecracker-package-test@0.1.0
```

Identity MUST bind:

- coordinate
- semantic version
- manifest digest
- content digest
- publisher identity
- registry snapshot hash

## Manifest Schema

Top-level fields:

- `schema_version`
- `artifact`
- `publisher`
- `kind`
- `version`
- `summary`
- `compatibility`
- `dependencies`
- `conflicts`
- `provides`
- `activation`
- `rollback`
- `trust`
- `replay`
- `files`

Kind-specific fields should live under `spec`.

## Dependency Graph

Dependencies are not only packages:

- `requires_artifact`: another AgentOS artifact.
- `requires_capability`: runtime capability semantics.
- `requires_policy`: policy baseline or stricter.
- `requires_runtime`: minimum `agentd`, `agent_core`, `security_execution` contract version.
- `requires_host_feature`: optional dependency such as KVM, Firecracker, apt, network.
- `requires_approval`: exact approval class for activation.

Dependency resolution MUST produce a deterministic graph and lockfile:

```text
ecosystem-lock.json
```

The lockfile should be recorded in release provenance.

## Registry Snapshot

Registry snapshot should be immutable and signed:

- `snapshot_id`
- `channel`
- `created_at`
- `expires_at`
- `root_metadata_digest`
- `artifacts[]`
- `revocations[]`
- `advisories[]`

Production should be able to run from a pinned local snapshot.

## State Storage

Suggested local paths:

- `/var/lib/agentos/ecosystem/registry/`
- `/var/lib/agentos/ecosystem/cache/`
- `/var/lib/agentos/ecosystem/staged/`
- `/var/lib/agentos/ecosystem/active/`
- `/var/lib/agentos/ecosystem/locks/`
- `/var/log/agentos/ecosystem/`

State records:

- `installed-artifacts.json`
- `active-artifacts.json`
- `activation-history.jsonl`
- `ecosystem-lock.json`
- `registry-snapshot.json`

## Compatibility

Compatibility MUST include:

- AgentOS distro version range.
- contract schema versions.
- target architecture.
- host feature requirements.
- optional dependency behavior.
- migration requirements.
- rollback support level.

## Migration Strategy

- Manifest schema versions must be forward-compatible by rejecting unknown required fields.
- Activation state migrations must be explicit and tested.
- Artifact downgrade must be blocked unless rollback contract says it is safe.
- Policy pack migration must produce diff and require approval when it broadens authority.

## Data Tasks

- `TASK-ECO-020`: Add artifact coordinate and manifest schema.
- `TASK-ECO-021`: Add registry snapshot and lockfile schema.
- `TASK-ECO-022`: Add activation report and installed/active state schema.
- `TASK-ECO-023`: Add compatibility and migration validation.
- `TASK-ECO-024`: Add revocation/advisory metadata model.
- `TASK-ECO-025`: Add deterministic hash projection for release provenance.
