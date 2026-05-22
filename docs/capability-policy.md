# Capability Policy

Task: `TASK-AIOS-007`

## Purpose

Semantic tools are converted into short-lived capability leases. The lease is bound to:

- actor
- tool
- resource
- parameter hash
- expiration
- policy version
- risk class

## Decision Model

| Risk | Decision without approval | Decision with exact approval |
|---|---|---|
| `read-only` | `allow` | `allow` |
| `write-with-diff` | `pause-for-approval` | `allow` |
| `execute-with-confirmation` | `pause-for-approval` | `allow` |
| `privileged-with-human-approval` | `pause-for-approval` | `allow` |
| `never` | `deny` | `deny` |

Approval tokens bind exact parameters through a stable hash. If the tool parameters change after approval, the token no longer matches.

## Denied Capabilities

Normal mode denies generic shell execution and any capability classified as `never`. Later tasks can add explicit deny entries for secret dumps, raw block writes, and kernel module loading as those semantic tools are introduced.

Denied decisions are still written as `PolicyEvaluated` audit events with actor, tool, resource, risk, policy version, and parameter hash metadata. They do not create a capability lease and do not write `EffectPrepared` or `EffectObserved`.

## CLI Verification

```powershell
cargo test -p agentd
cargo run -p agentd -- --policy-demo
Get-Content .workflow/artifacts/policy/demo.jsonl
```

The demo shows `fs.write.diff` pausing without approval, then issuing a lease with a matching exact approval token. It also records a denied `shell.exec` policy decision without preparing or observing an effect.
