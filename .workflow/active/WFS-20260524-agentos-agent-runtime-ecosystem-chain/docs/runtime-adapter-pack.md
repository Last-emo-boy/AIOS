# Runtime Adapter Pack

## Purpose

`runtime-adapter-pack` defines host or external adapters as typed semantic tools. It must not become a direct side-effect path.

The only valid side-effect path is:

```text
adapter semantic tool
  -> AgentCore PlanSpec
  -> policy and exact approval when required
  -> SecurityExecutionEngine
  -> audit and rollback
```

## Schema

Runtime contract:

```text
RuntimeAdapterPackV1
RuntimeAdapterToolBinding
```

Schema version:

```text
agentos.runtime-adapter-pack.v1
```

Required pack fields:

- `coordinate`: must use `runtime-adapter-pack`.
- `tool_bindings`: one or more semantic tool bindings.
- `requires_security_execution_engine`: must be true.
- `direct_host_mutation_allowed`: must be false.
- `replay_evidence_required`: must be true.

Tool binding fields:

- `tool_name`
- `risk_class`
- `policy_mapping`
- `required_dependency_features`
- `optional_dependency_features`
- `missing_optional_behavior`

## Rules

Tool names must be semantic lowercase identifiers such as `service.restart`. Shell surfaces such as `shell.exec`, `bash`, `cmd.exe`, `powershell` and generic `exec` are denied.

Every tool binding must map to a policy risk class and policy mapping. Adapter packs cannot omit risk class metadata.

Optional dependency loss must degrade before effects. It cannot trigger host mutation fallback.

All mutating operations require SecurityExecutionEngine authority and replay evidence.

## Failure Cases

Blocked by contract:

- arbitrary shell exposure
- missing policy mapping
- `RiskClass::Never` tool binding
- missing optional dependency with host mutation fallback
- direct host mutation
- activation without replay evidence

## Verification

Primary checks:

```powershell
cargo test -p runtime_contracts ecosystem
cargo test -p security_execution
powershell -ExecutionPolicy Bypass -File scripts\ecosystem-replay.ps1
```
