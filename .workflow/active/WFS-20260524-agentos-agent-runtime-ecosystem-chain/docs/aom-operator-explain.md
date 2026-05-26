# aom Operator Artifact Explain

## Purpose

`aom explain` is the operator-facing projection for AgentOS ecosystem artifacts. It explains what an artifact is, why it is trusted or blocked, what it may add after activation, and which runtime gates still apply.

The projection is read-only. It must not stage, activate, prepare effects, mutate active artifact state, or expose raw secret-like values.

## Schema

Current local lifecycle schema:

```text
agentos.aom-artifact-explain.v1
```

Required operator fields:

- `coordinate`: stable artifact coordinate in `agentos:<kind>/<publisher>/<name>@<version>` format.
- `artifact_kind`: policy, workflow, replay, model, knowledge, adapter, image or trust metadata kind.
- `trust_tier`: `core`, `verified`, `organization`, `community` or `local-dev`.
- `publisher`: publisher namespace from the coordinate.
- `source_uri`: source URI from the pinned local registry snapshot.
- `dependencies`: resolved dependency coordinates.
- `capabilities`: operator-readable capability summary.
- `risk`: current activation risk. In Wave 4 this is `activation-gated`.
- `activation_requirements`: required runtime authorities.
- `blocked_prerequisites`: missing tasks or gates.
- `replay_status`: replay expectation before activation.
- `revoked` and `advisory_refs`: revocation visibility from registry metadata.
- `staged`, `active` and `activation_prepared`: lifecycle state flags.
- `explanation_hash`: deterministic hash of the explained artifact record.

## Lifecycle Semantics

Wave 4 only supports local registry read, verification and inert staging:

```text
registry-only -> staged-only
```

It does not support:

```text
staged -> active
```

The projection must keep these flags explicit:

```json
{
  "staged": false,
  "active": false,
  "activation_prepared": false
}
```

After `aom stage`, staged artifacts remain inert and the active set remains unchanged.

## Activation Boundary

`aom activate` is blocked until activation is implemented through:

- `TASK-ECO-004`: AgentCore PlanSpec activation planning.
- `TASK-ECO-005`: SecurityExecutionEngine side-effect execution.

Activation must preserve:

- no normal-mode arbitrary shell
- exact approval
- secret handle-only policy
- source-to-sink policy
- audit range binding
- rollback handle binding

## Trust And Advisory Visibility

Operators must see trust tier, publisher, digest-bound advisory references and revocation status. A revoked artifact must remain explainable for diagnosis, but future activation is blocked. If a previously active artifact becomes revoked, later active-set projection must mark it degraded.

## Secret Policy

The explain projection may include identifiers, hashes, paths and advisory ids. It must not include raw secret values, credentials, tokens or untrusted instructions as executable guidance.

## Ownership

`agentd` may render this projection and expose `--aom explain`, but ecosystem resolution, verification and staging remain owned by `agent_core::ecosystem`. Activation remains owned by AgentCore PlanSpec plus SecurityExecutionEngine.
