# Functional Capability Architecture

## Module Ownership

| Layer | Owns | Must Not Own |
|---|---|---|
| `runtime_contracts` | Stable request/response types, capability matrix records, adapter status models | Execution, policy decisions, host mutation |
| `agent_core` | Workflow DAGs, run state, scheduling, observation processing, memory hints, capability orchestration | Direct tool execution, sandbox authority, raw secrets |
| `security_execution` | Policy, capability leases, sandbox profiles, effect envelopes, verification, rollback, audit, source-to-sink enforcement | Product workflow branching, TUI text, release packaging |
| `agentd` | PID 1 lifecycle, CLI/TUI/API projection, operator command composition, health reporting | New capability business logic, package manager mutations, content trust decisions |
| `packaging` and `scripts` | Rootfs artifacts, config defaults, smoke tests, release/provenance gates | Runtime authority or policy bypasses |

## Capability Pipeline

```text
IntentCtx
  -> PlanSpec / CapabilityWorkflow
  -> SemanticToolCall
  -> PolicyDecision
  -> CapabilityLease
  -> SandboxProfile
  -> EffectEnvelope
  -> VerificationResult
  -> CommitSealed | RollbackPending | FailedClosed
  -> RuntimeAuditProjection | OperatorProjection
```

## Adapter Families

### Package Manager

The package manager adapter should start as Debian/Ubuntu compatible, but its
contract must not hard-code `apt` into AgentCore. The adapter shape should be:

```text
PackageMetadataRequest -> PackageMetadata
IsolatedPackageInstallRequest -> IsolatedInstallReport
PackageSmokeRequest -> PackageSmokeReport
HostPackagePromotionRequest -> HostPromotionPlan
HostPackageVerifyRequest -> HostPackageVerifyReport
```

The host promotion step remains `privileged-with-human-approval`.

### Untrusted Content

The content adapter should support local fixture fetch first, then network fetch
behind pinned digest and size limits.

```text
ContentFetchRequest -> ContentArtifact
ContentSanitizeRequest -> SanitizedContent
ContentSummaryRequest -> ContentSummary
SourceToSinkCheckRequest -> SourceToSinkDecision
```

External content stays `external-untrusted`; sanitized summaries are replanning
context only.

### Firecracker

Firecracker is an executor profile behind `security_execution`, not a separate
workflow engine. The adapter should separate dependency probe, VM plan,
execution report, and artifact retention.

```text
FirecrackerProbe -> FirecrackerAvailability
MicroVmExecutionPlan -> MicroVmRunReport
MicroVmArtifactManifest -> RetainedArtifactSet
```

Missing KVM, Firecracker, jailer, kernel, or rootfs must fail before
`EffectPrepared`.

### Operator UX

Operator commands should expose workflow state without granting new authority:

- `agentd --capability-matrix`
- `agentd --plan-preview <intent>`
- `agentd --approve <run> <step> <token>`
- `agentd --deny <run> <step>`
- `agentd --audit-project <journal> [run]`
- `agentd --rollback <rollback-id>`
- `agentd --support-bundle <run>`

All commands must be projections or semantic entry points; they must not become
raw host shell wrappers.

## Release Gate Shape

The functional release gate should run local-only fixture-backed workflows:

- service recovery approved and denied,
- package install denied, isolated success, and host promotion approval binding,
- untrusted content injection denial,
- Firecracker missing dependency fail-closed,
- rollback and support bundle redaction,
- audit projection and provenance hash stability.

QEMU remains optional for fast local development but mandatory before promotion
when `E:\qemu\qemu-system-x86_64.exe` is available.
