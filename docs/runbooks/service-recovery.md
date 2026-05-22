# Service Recovery Runbook

Task: `TASK-AIOS-010`

## Scenario

The first MVP runbook is a local `nginx` recovery flow for a 502-style outage. The implementation uses a deterministic project fixture so tests do not depend on the host actually running nginx.

## Flow

1. Record `IntentReceived` and freeze a plan.
2. Run read-only diagnostics without approval:
   - `svc.logs service=nginx last=200`
   - `svc.status service=nginx`
   - `http.check url=http://127.0.0.1/healthz`
   - `config.test service=nginx`
3. Compile each read-only lease through the sandbox profile and seal observed diagnostic results.
4. Evaluate `svc.restart service=nginx` as `execute-with-confirmation`.
5. In production-sensitive mode, pause for approval before any restart effect is prepared.
6. If approved, prepare and observe the simulated restart, then verify final health with `svc.status` and `http.check`.
7. Render a final operator summary grounded in observed audit events.

## Safety Properties

- read-only diagnostics require no approval and have no persistent side effects
- denied restart never writes an `EffectPrepared` event for `svc.restart`
- approved restart has `ApprovalBound`, `EffectPrepared`, `EffectObserved`, and `CommitSealed`
- final health is based on observed fixture state, not model output

## Verification

```powershell
cargo test -p agentd
cargo run -p agentd -- --service-recovery-demo approved .workflow/artifacts/service-recovery/demo-approved.jsonl
cargo run -p agentd -- --service-recovery-demo denied .workflow/artifacts/service-recovery/demo-denied.jsonl
cargo run -p agentd -- --audit-show .workflow/artifacts/service-recovery/demo-approved.jsonl run-service-recovery
```
