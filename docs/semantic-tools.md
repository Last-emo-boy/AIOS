# Semantic Tools

Task: `TASK-AIOS-004`

## Purpose

The semantic tool router is the normal-mode tool boundary. `agentd` accepts typed semantic tool calls, validates parameters, canonicalizes them for audit, and rejects generic shell access.

## Tool Schemas

| Tool | Risk | Required parameters | Optional parameters |
|---|---|---|---|
| `svc.logs` | `read-only` | `service` | `last` |
| `svc.status` | `read-only` | `service` | |
| `http.check` | `read-only` | `url` | |
| `config.test` | `read-only` | `service` | |
| `fs.read` | `read-only` | `path` | |
| `fs.write.diff` | `write-with-diff` | `path`, `content_hash` | `base_hash` |
| `svc.restart` | `execute-with-confirmation` | `service` | |
| `audit.show` | `read-only` | `run` | |
| `rollback.trigger` | `execute-with-confirmation` | `rollback_id` | |

`shell.exec` is intentionally absent from the schema table and is denied explicitly in normal mode.

## CLI Verification

Accepted route:

```powershell
cargo run -p agentd -- --route-tool svc.logs service=nginx last=200
```

Denied shell:

```powershell
cargo run -p agentd -- --route-tool shell.exec cmd=id
```

Write-with-diff representation:

```powershell
cargo run -p agentd -- --route-tool fs.write.diff path=/etc/nginx/nginx.conf content_hash=abc
```

## Audit Fields

The router returns:

- `tool`
- `version`
- `risk`
- `decision`
- `normalized_params`

Downstream audit and policy tasks should store these normalized fields before executor invocation.
