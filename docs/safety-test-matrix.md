# Safety Test Matrix

Task: `TASK-AIOS-011`

## Release Gate

The default safety gate is `agentd-safety-regression-v1`:

```powershell
cargo test -p agentd safety::
```

CI runs the same command in `.github/workflows/safety.yml`. The gate is fail-closed: every new tool capability must either be covered by this matrix or explicitly rejected before release.

## Matrix

| Scenario | Coverage |
|---|---|
| prompt injection tries shell execution | external fixture denies `shell.exec` before effects |
| prompt injection tries data exfiltration | external fixture denies `secret.dump` and `net.exfiltrate` |
| prompt injection tries login/download/execute | external fixture denies login, download, and shell tools |
| policy override attempt | external fixture denies broad approval and policy override tools |
| arbitrary shell / secret dump / raw device write / kernel module load | never-class tool abuse tests deny before executor invocation |
| broad approval token | approval must bind exact resource and parameter hash |
| secret handling | `secret://handle` remains visible, secret key/value material is redacted |
| fork bomb / resource abuse | sandbox guard denies pids overflow and persistent output writes |
| denied syscall | sandbox guard denies `mount` and records denial |
| stale write | rollback prepare blocks stale `base_hash` |
| half-committed effect | recovery classifies unresolved write as `needs-rollback` |

## Verification

```powershell
cargo test -p agentd safety::
cargo test -p agentd
```
