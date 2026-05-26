# System Architect Analysis

## Architecture Thesis

AgentOS 的生态层应该是一个 **artifact activation control plane**，而不是一个传统 package installer。`aom` 可以像 APT 一样提供 search、fetch、verify、stage、activate 和 rollback，但它管理的是 AgentOS runtime 的受控行为面。

核心结构：

```text
Registry Snapshot
  -> Artifact Resolver
  -> Trust Verifier
  -> Staging Store
  -> Activation Planner
  -> SecurityExecutionEngine
  -> Runtime Projection
  -> Release / Replay Gate
```

`agentd` 只能展示 projection 和接收 operator command。artifact resolution、policy merge、workflow compilation、adapter validation 和 replay gate 不应塞进 `agentd`。

## Component Model

| Component | Owner | Responsibility |
| --- | --- | --- |
| `runtime_contracts::ecosystem` | `runtime_contracts` | Artifact manifest、registry snapshot、activation report、rollback report、trust metadata schema |
| `agent_core::ecosystem` | `agent_core` | Resolve requested artifact set, build activation PlanSpec, compile workflow packs into runtime plans |
| `security_execution::ecosystem_activation` | `security_execution` | Verify policy, lease, sandbox, side-effect envelope, rollback and audit rules for activation |
| `agentd::ecosystem_projection` | `agentd` | Read-only operator view: installed/staged/blocked/active artifacts and why |
| `scripts/ecosystem-replay.ps1` | `scripts` | Local-only registry fixture replay and promotion evidence |
| `packaging/agentos/rootfs/etc/agentos/ecosystem/` | `packaging` | Built-in registry snapshot, default policy pack, workflow pack fixtures |

## Trust Boundaries

- Registry metadata is untrusted until signature, digest and channel policy verify.
- Artifact installation is only staging. It MUST NOT change runtime behavior.
- Activation is a side effect and MUST go through SecurityExecutionEngine.
- Policy packs can narrow policy but MUST NOT remove baseline invariants.
- Workflow packs can generate PlanSpec but MUST NOT execute host mutation.
- Adapter packs can expose typed tools but MUST NOT bypass semantic tool registry.

## Data Model

Entities:

- `ArtifactManifest`: identity, kind, version, publisher, digest, dependencies, compatibility, activation contract.
- `RegistrySnapshot`: channel, index version, manifest list, root metadata hash, revocation list.
- `StagedArtifact`: local path, verified digest, source snapshot, staging timestamp, activation status.
- `ActivationPlan`: resolved artifact graph, policy merge preview, required approvals, rollback scope.
- `ActivationReport`: activated artifacts, denied artifacts, audit ranges, replay evidence, rollback handles.

## State Machine

```text
Discovered -> Fetched -> Verified -> Staged -> ActivationPlanned
  -> AwaitingApproval -> Activating -> Active -> Deactivating -> RolledBack
  -> Blocked | FailedClosed
```

Important rule: `Verified` and `Staged` are not operational states. They mean only “available locally”.

## Error Handling

- Unknown artifact kind: fail closed at resolution.
- Missing optional runtime dependency: block activation before `EffectPrepared`.
- Policy conflict: produce diff/explain and require explicit decision or reject.
- Manifest compatibility mismatch: block activation with exact version constraint.
- Revoked publisher or artifact digest: deactivate on next policy sync or block promotion.
- Replay failure: keep staged artifacts but do not activate.

## Observability

Minimum metrics:

- `ecosystem.registry_snapshot_age_seconds`
- `ecosystem.artifact_resolution_failures_total`
- `ecosystem.artifact_activation_denied_total`
- `ecosystem.policy_merge_conflicts_total`
- `ecosystem.replay_pass_rate`
- `ecosystem.rollback_success_total`
- `ecosystem.revoked_artifact_present_total`
- `ecosystem.activation_latency_ms`

## Configuration Model

Production Distro should ship:

- `/etc/agentos/ecosystem/channels.json`
- `/etc/agentos/ecosystem/trust-roots.json`
- `/etc/agentos/ecosystem/default-policy-pack.json`
- `/etc/agentos/ecosystem/registry-snapshot.json`
- `/var/lib/agentos/ecosystem/staged/`
- `/var/lib/agentos/ecosystem/active/`
- `/var/lib/agentos/ecosystem/cache/`

## Architectural Tasks

- `TASK-ECO-001`: Define `runtime_contracts::ecosystem` manifest and registry snapshot schema.
- `TASK-ECO-002`: Add local registry fixture and artifact resolver.
- `TASK-ECO-003`: Implement staging store with digest and signature verification report.
- `TASK-ECO-004`: Implement activation planning through AgentCore PlanSpec.
- `TASK-ECO-005`: Route activation side effects through SecurityExecutionEngine.
- `TASK-ECO-006`: Add read-only operator projection in `agentd`.
