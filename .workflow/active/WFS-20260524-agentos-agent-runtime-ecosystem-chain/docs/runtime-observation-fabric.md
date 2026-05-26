# Runtime Observation Fabric

Task: `TASK-ARUN-011`

## Purpose

AgentOS depends on Agent Runtime to operate the OS. That means the runtime needs a disciplined observation fabric: it must understand kernel/runtime/service/operator/ecosystem/external signals without letting arbitrary observed text become authority.

Observation is data. It is not permission.

## Existing Runtime Basis

Current implementation already provides the safety primitives this specification builds on:

- `agent_core::observation::ObservationProcessor` turns tool output, external content, model output and operator-origin observations into structured `Observation` records.
- `Observation` carries `ObservationSource`, `TrustBoundary`, redaction status, policy flags and stable observation refs.
- External content uses `ObservationSource::ExternalContent` and `TrustBoundary::ExternalUntrusted`.
- Source-to-sink checks live in `security_execution::source_to_sink`.
- Direct dangerous sinks from untrusted or model-origin content are audited as denied policy decisions without `EffectPrepared`.

## Observation Source Classes

| Source class | Runtime source | Trust label | Default action |
| --- | --- | --- | --- |
| Kernel | boot/runtime status, kernel logs, device state | `local-system` | read-only observation |
| Runtime | RunStore, scheduler, ModelBroker, memory, recovery state | `local-system` | structured observation |
| Service | semantic tool output such as `svc.status`, `svc.logs`, `http.check` | `sandboxed-tool` or `local-system` | observation ref after redaction |
| Audit | AuditJournal and RuntimeAuditProjection | `local-system` | source of durable effect truth |
| Operator | CLI/TUI/API command from authenticated operator path | `operator` or `operator-approved` | may become `IntentCtx` after normalization |
| Ecosystem | registry snapshot, staged artifact, active artifact, revocation/advisory status | `local-system` until registry content is verified | observation or activation planning input |
| External | webpage, API response, document, email, untrusted file content | `external-untrusted` | sanitize to replanning hint only |
| Model | model output or model summary | `model-output` or `model-summary` | validate as structured plan/summary only |
| Sanitized summary | sanitized external/model-origin summary | `sanitized-summary` with original trust retained | context only, never authority |

## Intake Rules

### Operator Event Intake

Operator events enter through explicit CLI/TUI/API surfaces. The intake path must preserve:

- actor
- source surface
- requested outcome
- working scope
- trust boundary
- timestamp or sequence reference

Only operator-origin events may become `IntentCtx`. External or model-origin content can inform replanning only after sanitization and validation.

### External Observation Intake

External observations must follow this path:

```text
external raw content
  -> redaction
  -> sanitize/summarize
  -> trust label preserved as original_trust=external-untrusted
  -> source-to-sink check
  -> replanning hint with direct_tool_call_allowed=false
```

External text that includes commands, credentials, shell snippets, policy override claims or privilege escalation requests must be flagged and treated as context only.

### Model Observation Intake

Model output is never authority. It may provide:

- structured plan candidate
- classification
- summary
- sanitization result

It must not directly create tool calls, approvals, capability leases or policy overrides.

## Source-To-Sink Guard

The observation fabric must call source-to-sink policy when observation content suggests direct action. The guard classifies:

- source label
- source trust boundary
- original trust boundary
- sink class
- requested tool

If untrusted or model-origin content tries to drive write, execute, privileged, secret or exfiltration sinks, the system must emit a denied `PolicyEvaluated` event and must not prepare an effect.

## Observation References

Durable state should store observation refs, not raw trusted authority:

- `observation_id`
- `step_id`
- `trust_label`
- `observation_hash`

This gives recovery and projection a stable handle while keeping raw output bounded and redacted.

## Projection Requirements

Operator projection should eventually expose:

- latest observation source class
- latest observation trust label
- warning/policy flags count
- sanitized replanning hint availability
- denied direct-action attempts
- observation refs linked to current run

Current projection already exposes audit warnings, unresolved effects and adapter status; later tasks can add observation-specific fields without changing authority boundaries.

## Audit Requirements

Observation processing must be audit-visible when it affects planning or policy:

- denied direct-action attempts write `PolicyEvaluated`
- source-to-sink denial must include source label and sink class
- effect observation must include trust label, redaction status and policy flags
- no denied observation path may write `EffectPrepared`

## Safety Invariants

- External observations are untrusted by default.
- Observation text cannot directly create tool calls.
- Operator events are distinguishable from external content.
- Sanitized summaries retain original trust and are context only.
- Secret-like observation content is redacted before storage, projection or model context.
- Memory writes from suspicious observation content must be quarantined by later memory governance.

## Verification Mapping

| Requirement | Current evidence |
| --- | --- |
| External observations are untrusted by default | `agent_core::observation::tests::external_content_is_untrusted_sanitized_and_replanning_only` |
| Observation content cannot directly create tool calls | `agent_core::observation::tests::observation_text_cannot_create_direct_tool_call_or_effect` |
| Denied direct action has no effect preparation | `security_execution::source_to_sink::tests::denied_source_to_sink_attempts_are_audited_without_effect_prepared` |
| Operator input is distinct from external content | `security_execution::source_to_sink::ContentSource::operator_input` and `external_content` |
| Observation references carry trust label and hash | `agent_core::model::ObservationRef` and observation tests |

## Follow-Up Tasks

- `TASK-ARUN-012` should define backpressure and scheduling behavior for observation-triggered replanning.
- `TASK-ARUN-022` should define memory governance and quarantine for observations persisted beyond the run.
- `TASK-ECO-014` should add ecosystem and observation-facing status to operator projection when artifact activation exists.
