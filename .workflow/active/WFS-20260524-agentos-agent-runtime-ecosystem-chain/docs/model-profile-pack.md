# Model Profile Pack

## Purpose

`model-profile-pack` defines model routing profiles as ecosystem artifacts. It does not make a remote model part of the boot baseline and it does not let workflows call providers directly.

The only supported runtime path is:

```text
workflow / planner intent
  -> AgentCore ModelBroker
  -> selected model profile
  -> local, stub or policy-gated remote provider
  -> bounded model evidence
```

## Schema

Runtime contract:

```text
ModelProfilePackV1
ModelEndpointProfile
ModelProviderMode
ModelRuntimeRole
```

Schema version:

```text
agentos.model-profile-pack.v1
```

Required fields:

- `coordinate`: must use `model-profile-pack`.
- `profiles`: one or more endpoint profiles.
- `baseline_provider_modes`: must include `stub` or `local`.
- `remote_optional`: remote providers are optional only.
- `policy_gate_required`: required when any remote provider exists.
- `broker_required`: must be true.

Endpoint fields:

- `profile_id`
- `provider_mode`: `stub`, `local` or `remote-optional`
- `provider_label`
- `allowed_roles`: `plan`, `classify`, `summarize`, `sanitize`
- `remote_policy_gate`
- `credential_handle_refs`
- `direct_provider_execution_allowed`
- `broker_required`

## Rules

Stub or local provider remains the baseline. Production Distro boot, replay and release gates cannot require a remote model.

Remote providers must be `remote-optional` and policy-gated. Missing remote provider availability degrades behavior instead of blocking local replay.

Credentials must be represented as single-token `secret://` handles. Raw `token=`, `password=`, `api_key=` or similar values fail contract validation.

`direct_provider_execution_allowed` must be false. Workflows and ecosystem activation cannot bypass ModelBroker.

## Failure Cases

Blocked by contract:

- remote provider without a policy gate
- model profile without stub or local baseline
- raw credential values
- direct provider execution
- missing ModelBroker requirement

## Verification

Primary checks:

```powershell
cargo test -p runtime_contracts ecosystem
cargo test -p agent_core model_broker
powershell -ExecutionPolicy Bypass -File scripts\ecosystem-replay.ps1
```

Adversarial fixtures live under:

```text
packaging/agentos/fixtures/ecosystem/adversarial/model-knowledge/
```
