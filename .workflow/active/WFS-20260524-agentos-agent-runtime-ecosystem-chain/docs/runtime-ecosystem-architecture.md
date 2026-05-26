# Runtime Ecosystem Architecture

## Unified Architecture

The ecosystem manager, `aom`, extends AgentOS by adding AgentOS-native artifacts. It does not bypass the OS runtime. Artifact activation is just another high-level AgentOS operation, so it must become a PlanSpec and pass through SecurityExecutionEngine.

```text
aom command / operator intent
  -> artifact resolver
  -> manifest and trust verification
  -> staging store
  -> activation planner
  -> AgentCore PlanSpec
  -> SecurityExecutionEngine
  -> audit / rollback / projection
```

This keeps ecosystem growth from turning into a second privileged runtime.

## Artifact Kinds

First-class ecosystem artifact kinds:

- `capability-pack`: defines capability semantics and lease constraints.
- `semantic-tool-pack`: defines tool schema, risk and adapter contract.
- `policy-pack`: defines policy rules, approval requirements and source-to-sink rules.
- `workflow-pack`: defines reusable AgentCore runbooks.
- `model-profile-pack`: defines local/stub/optional remote model routing.
- `knowledge-pack`: defines retrieval content with trust labels.
- `runtime-adapter-pack`: defines typed host or external adapters.
- `execution-image-pack`: defines sandbox rootfs, guest image, update bundle or Firecracker image.
- `test-replay-pack`: defines local replay, adversarial fixtures and compatibility gates.
- `trust-metadata-pack`: defines signatures, provenance, SBOM, revocation and advisories.

The first implementation slice should only activate `policy-pack`, `workflow-pack` and `test-replay-pack`. Other kinds can be modeled but should remain inactive or fixture-only until the first gate is solid.

## Data Contracts

Proposed module:

```text
crates/runtime_contracts/src/ecosystem.rs
```

Initial contracts:

- `ArtifactCoordinate`
- `AgentOsArtifactManifestV1`
- `RegistrySnapshotV1`
- `EcosystemLockV1`
- `ArtifactVerificationReportV1`
- `ArtifactStagingReportV1`
- `ActivationPlanV1`
- `ActivationReportV1`
- `ActiveArtifactSetV1`
- `RevocationAdvisoryV1`

Coordinate format:

```text
agentos:<kind>/<publisher>/<name>@<version>
```

## Local State

Suggested distro paths:

```text
/etc/agentos/ecosystem/channels.json
/etc/agentos/ecosystem/trust-roots.json
/etc/agentos/ecosystem/default-registry-snapshot.json
/var/lib/agentos/ecosystem/registry/
/var/lib/agentos/ecosystem/cache/
/var/lib/agentos/ecosystem/staged/
/var/lib/agentos/ecosystem/active/
/var/lib/agentos/ecosystem/locks/
/var/log/agentos/ecosystem/
```

Staged artifacts must be inert. Active artifacts must be recoverable and explainable.

## Activation Boundary

`aom activate` must not mutate runtime state directly. It should:

1. Resolve and verify artifact set.
2. Produce activation diff and compatibility report.
3. Ask AgentCore to create an activation PlanSpec.
4. Let SecurityExecutionEngine evaluate policy and prepare effects.
5. Require exact approval where activation broadens authority.
6. Record audit range and rollback handles.
7. Update active artifact set only after verification succeeds.

## Trust Model

Trust tiers:

- `core`: shipped with AgentOS release and covered by release gate.
- `verified`: signed publisher and verified channel replay.
- `organization`: locally approved overlays and allowlists.
- `community`: discoverable, sandbox-only by default.
- `local-dev`: explicit developer mode, not production-promotable by default.

Policy packs may narrow authority. They must not disable no-shell, exact approval, secret handle, source-to-sink, audit or rollback invariants.

## Failure Modes

- Registry unavailable: use pinned local snapshot.
- Signature missing: block production activation.
- Digest mismatch: fail closed before staging.
- Compatibility mismatch: block activation and explain required versions.
- Revoked artifact: block future activation and mark active set degraded.
- Policy conflict: produce diff and require explicit operator decision or reject.
- Replay failure: staged artifact stays inert.

## Integration With Existing Functional Matrix

Existing capabilities become ecosystem candidates:

- package workflow -> workflow pack + adapter pack later
- untrusted content workflow -> workflow pack + semantic tool pack
- Firecracker fail-closed profile -> execution image pack later
- support bundle -> workflow pack + projection contract
- operator commands -> core command registry artifact later

The first wave should avoid moving all existing capabilities into `aom`; instead, it should prove the artifact lifecycle and activation boundary with small built-in samples.
