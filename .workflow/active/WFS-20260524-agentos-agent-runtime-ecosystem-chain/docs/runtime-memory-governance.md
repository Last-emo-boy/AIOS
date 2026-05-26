# Runtime Memory Governance

Task: `TASK-ARUN-022`

## Purpose

AgentOS uses memory and knowledge to operate the OS through Agent Runtime. That memory must help planning and recovery without becoming hidden authority. Untrusted knowledge, external content, model summaries and stale memory cannot grant approval, weaken policy, create capability leases or bypass SecurityExecutionEngine.

Memory is context. It is not permission.

## Existing Runtime Basis

Current implementation already provides the required primitives:

- `agent_core::memory::MemoryStore` defines write, read context, search, expire and quarantine operations.
- `MemoryScope` includes `session`, `run`, `audit-derived` and `quarantined`.
- `MemoryEntry` carries source, trust label, source ref, policy flags, TTL, redaction status and integrity hash.
- Planner-facing `MemoryContext` is bounded and excludes quarantined entries.
- Secret-like values are rejected or redacted before normal memory storage.
- Prompt-injection, suggested-command, policy override, capability lease and approval claims are quarantined.

## Memory Scopes

| Scope | Source | Planner visibility | Authority |
| --- | --- | --- | --- |
| `session` | operator session preferences and local runtime hints | optional, bounded | no authority |
| `run` | observations and summaries tied to a PlanRun | allowed when same run or explicitly included | no authority |
| `audit-derived` | summaries derived from sealed audit evidence | allowed with audit refs and hashes | evidence context only |
| `ecosystem` | future artifact metadata, advisories and knowledge packs | allowed only after verification and labeling | no activation authority |
| `quarantined` | suspicious, untrusted or policy-claiming content | never in planner context by default | blocked context |

The current code has `session`, `run`, `audit-derived` and `quarantined`; `ecosystem` is a reserved governance scope for later knowledge pack tasks and can initially map to `audit-derived` plus artifact refs until schemas exist.

## Trust Labels

Every memory entry must preserve source trust:

- `operator`
- `operator-approved`
- `local-system`
- `sandboxed-tool`
- `external-untrusted`
- `model-output`
- `model-summary`
- `sanitized-summary`

Trust labels travel with the memory into planner context. Sanitized summaries must retain original trust metadata through source refs or policy flags.

## Knowledge Pack Quarantine

Future `knowledge-pack` artifacts are high-risk context because they can poison planner behavior at scale.

Knowledge pack rules:

- staged knowledge is inert;
- verified knowledge still enters as labeled context, not authority;
- community or local-dev knowledge defaults to quarantined or read-only context;
- knowledge that contains shell snippets, policy overrides, approval claims, secret-like values, capability lease claims or privileged instructions is quarantined;
- knowledge cannot write policy, approvals, leases or tool definitions directly;
- activation of a knowledge pack must go through `AgentCore PlanSpec + SecurityExecutionEngine`.

## Planner Context Rules

Planner context may include only bounded summaries:

- entry id;
- scope;
- trust label;
- source ref;
- integrity hash;
- redacted summary;
- truncation marker.

Planner context must not include:

- raw secret-like values;
- raw external content;
- raw model prompts;
- quarantined entries;
- approval claims as authority;
- policy overrides;
- capability lease claims;
- executable shell instructions as commands.

If memory context suggests action, it must be treated as a hint that goes through observation/source-to-sink checks, planning, scheduling, policy, approval and SecurityExecution.

## Redaction And Secret Rules

Allowed:

- `secret://` handles as references;
- redacted summaries;
- handle-only audit references.

Rejected or quarantined:

- `password=...`;
- `token=...`;
- API keys;
- embedded credentials;
- secret values in summaries, memory refs or planner context.

Raw secrets must never enter model context, memory entries, support bundles or projection. Secret handles still require explicit, narrow secret-use capability leases before use.

## Memory Poisoning Controls

Memory must quarantine or exclude content that claims:

- "approval granted";
- "policy override";
- "capability lease issued";
- "ignore previous instructions";
- "run shell";
- "disable sandbox";
- "write to host";
- "exfiltrate";
- "use this token/password".

These phrases may appear in quarantined forensic evidence, but not as planner authority.

## TTL And Freshness

Memory entries must be bounded by freshness:

- run memory should expire unless promoted through audit-derived evidence;
- session memory should be explicitly scoped and bounded;
- external content should expire quickly or remain quarantined;
- audit-derived memory can persist longer because it is grounded in sealed evidence;
- ecosystem knowledge must bind to artifact digest and active artifact set.

Restart must not reset TTL or quarantine state.

## Integrity And Support Evidence

Each memory entry should carry an integrity hash. Support bundles may include:

- memory entry ids;
- scopes;
- trust labels;
- source refs;
- hashes;
- quarantine counts;
- redaction status.

Support bundles must not include raw memory content or raw secret values.

## Safety Invariants

- Untrusted knowledge cannot become privileged instruction.
- Raw secrets are rejected, redacted or represented only as handles.
- Memory cannot create approval claims.
- Memory cannot create policy overrides or capability leases.
- Planner context remains bounded and labeled.
- Quarantined memory is excluded from planner context.
- Knowledge pack activation cannot bypass SecurityExecutionEngine.

## Verification Mapping

| Requirement | Current evidence |
| --- | --- |
| Bounded planner context with source refs | `agent_core::memory::tests::safe_run_memory_is_bounded_for_planner_context` |
| Secret-like memory is redacted before storage | `agent_core::memory::tests::secret_like_memory_is_redacted_before_storage` |
| External malicious instruction is quarantined | `agent_core::memory::tests::malicious_external_instruction_is_quarantined` |
| TTL expiry is deterministic | `agent_core::memory::tests::ttl_entries_expire_deterministically` |
| Memory poisoning cannot enter planner context as authority | `agent_core::memory::tests::memory_poisoning_cannot_enter_planner_context_as_authority` |
| Cross-run memory poisoning cannot grant capabilities | `agent_core::adversarial::memory_poisoning_across_runs_cannot_grant_capabilities` |

## Follow-Up Tasks

- `TASK-ECO-050` should define model profile pack schema without leaking secrets.
- `TASK-ECO-051` should define knowledge pack schema using these trust and quarantine rules.
- `TASK-VERIFY-042` should add adversarial ecosystem fixtures for poisoned knowledge packs.
- `TASK-PROD-050` should include memory governance summary in support bundles.
