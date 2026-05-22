# Terminal-First Operator Flow

Task: `TASK-AIOS-003`

## Boundary

The MVP native interaction surface is terminal-first. The TUI is a projection of `agentd` state; it is not the security boundary. Plan generation, policy evaluation, approval state, effect observation, and audit events are all represented through structured `agentd` APIs.

## Supported Modes

Render a deterministic demo:

```powershell
cargo run -p agentd -- --tui-demo "recover local service" approved
```

Render denial audit:

```powershell
cargo run -p agentd -- --tui-audit-json "recover local service"
```

Start a minimal interactive loop:

```powershell
cargo run -p agentd -- --tui-interactive
```

## Approval States

The terminal surface supports:

- `approved`
- `denied`
- `timed_out`
- `suspended`

Only `approved` in the demo invokes the stub effect path. Other states render audit decisions without observing an effect.

## Service Recovery Preview

The first workflow family is local service recovery. The stub planner currently emits a read-only `svc.status` step so the operator can inspect a frozen plan preview before later tasks add real service tools.

## Verification

```powershell
cargo test -p agentd
cargo run -p agentd -- --tui-demo "recover local service" approved
cargo run -p agentd -- --tui-demo "recover local service" denied
cargo run -p agentd -- --tui-audit-json "recover local service"
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -TimeoutSeconds 30
```
