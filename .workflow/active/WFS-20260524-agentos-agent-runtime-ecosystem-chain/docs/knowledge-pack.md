# Knowledge Pack

## Purpose

`knowledge-pack` defines retrieval content as bounded, source-labeled context. It is not policy, approval or authority. Knowledge can help AgentCore plan, but it cannot grant capabilities, claim approval or rewrite privileged policy.

The runtime path is:

```text
knowledge artifact
  -> trust label and provenance check
  -> quarantine or sanitization
  -> bounded planner context
  -> AgentCore planning as evidence only
```

## Schema

Runtime contract:

```text
KnowledgePackV1
KnowledgeSourceV1
KnowledgeTrustLabel
MemoryScope
```

Schema version:

```text
agentos.knowledge-pack.v1
```

Required pack fields:

- `coordinate`: must use `knowledge-pack`.
- `sources`: one or more source entries.
- `planner_context_bounded`: must be true.
- `source_labels_required`: must be true.
- `approval_claims_allowed`: must be false.
- `privileged_policy_instructions_allowed`: must be false.

Required source fields:

- `source_id`
- `provenance_uri`
- `content_digest`
- `trust_label`
- `ttl_seconds`
- `allowed_memory_scope`
- `quarantined`
- `bounded_context_bytes`

## Trust Labels

Supported labels:

- `core-curated`
- `organization-curated`
- `community-reviewed`
- `untrusted`
- `suspicious`

`untrusted` and `suspicious` sources must use `allowed_memory_scope=quarantined` and `quarantined=true`.

## Rules

Knowledge entering planner context must be bounded by byte limit and TTL.

Planner context must retain source labels, provenance and digest references so support bundles can explain where advice came from.

Knowledge packs cannot create approval claims. Exact approval only comes from the approval subsystem.

Knowledge packs cannot carry privileged policy instructions. Policy authority remains in policy packs and SecurityExecutionEngine decisions.

## Failure Cases

Blocked by contract:

- missing trust label
- zero TTL
- unbounded context
- suspicious or untrusted source outside quarantine
- approval claim injection
- privileged policy override attempt
- raw secret-like values

## Verification

Primary checks:

```powershell
cargo test -p runtime_contracts ecosystem
cargo test -p agent_core memory
cargo test -p agentd agent_core::adversarial
powershell -ExecutionPolicy Bypass -File scripts\ecosystem-replay.ps1
```
