# agentd Lifecycle Skeleton

Task: `TASK-AIOS-002`

## Purpose

`agentd` is the MVP control-plane skeleton for the Developer VM first path. The current implementation is deliberately deterministic:

- run mode: `local-only`
- planner mode: `stub`
- arbitrary shell: disabled
- external LLM: not required

## Module Boundaries

The skeleton exposes the required module boundaries:

- Planner
- Policy
- Capability
- Tool Router
- Audit
- Rollback
- Model Broker
- TUI

Every module starts as `stub_ready`. This keeps PID 1 minimal while allowing later tasks to replace stubs with real adapters.

## Internal API Surface

The lifecycle skeleton includes typed stubs for:

```text
Plan(IntentCtx) -> PlanSpec
Classify(PlanStep) -> RiskClass
Evaluate(PlanStep) -> PolicyDecision
Acquire(PolicyDecision) -> CapabilityLease
Invoke(CapabilityLease, SemanticToolCall) -> Effect
Verify(Effect) -> VerificationResult
Commit(Effect) -> CommitId
Rollback(CommitId) -> RollbackResult
Recover() -> ReconciledState
```

The stubs do not perform persistent side effects. `shell.exec` is denied in normal mode.

## CLI Checks

Health:

```powershell
cargo run -p agentd -- --health
```

Controlled error:

```powershell
cargo run -p agentd -- --simulate-error
```

Plan preview:

```powershell
cargo run -p agentd -- --plan-preview "check local service"
```

Stub invocation:

```powershell
cargo run -p agentd -- --invoke-stub
```

## Verification

```powershell
cargo test -p agentd
cargo run -p agentd -- --health
cargo run -p agentd -- --simulate-error
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -TimeoutSeconds 30
```

The boot smoke test still uses the generated `/sbin/agentd` placeholder from `TASK-AIOS-001`. Later work can replace that placeholder with this Rust binary once cross-compilation/static-linking is finalized.
