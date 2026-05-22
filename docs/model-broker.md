# Model Broker

Source: `TASK-ACR-003`

`ModelBroker` is the only allowed model access boundary for Agent Core.
AgentCore, Planner, Scheduler, Policy, tools, sandbox, audit, rollback, and
recovery must not call model providers directly.

## Contract

`agent_core::model_broker::ModelBroker` exposes four structured operations:

- `plan`: drafts a bounded structured plan candidate and validates it into `PlanSpec`.
- `classify`: returns bounded labels for routing and triage.
- `summarize`: returns bounded summaries from already redacted text.
- `sanitize`: strips untrusted instruction-like content from already redacted text.

Every request carries:

- `request_id`
- operation-specific redacted input
- timeout
- max output size
- cancellation flag

Every successful response carries:

- `provider_id`
- `model_id`
- `model_digest`
- `prompt_template_version`
- `response_hash`
- `latency_ms`
- `confidence`
- `output_bytes`

Call logs include metadata and status only. They do not include raw prompts,
raw observations, or secret-like values.

## Fail-Closed Rules

ModelBroker failures cannot execute tools.

| Condition | Required state |
| --- | --- |
| Cancelled request | `Suspended` |
| Timeout | `Suspended` |
| Provider failure | `FailedClosed` |
| Oversized output | `FailedClosed` |
| Malformed output | `FailedClosed` |
| Secret-like input | `FailedClosed` |

Planner output remains advisory. A valid `PlanSpec` can mention risk hints, but
policy evaluation remains authoritative and happens later in the Security
Execution Foundation.

## Stub Provider

`StubModelProvider` is deterministic and local-only. It never opens a network
connection and returns valid structured responses for tests. Its plan output is
validated through the same ModelBroker boundary used by future providers.

The stub provider supports test modes for:

- healthy structured responses
- timeout
- provider failure
- malformed plan output

Malformed plan output is rejected before it becomes a `PlanSpec`.

## Provider Slots

Future providers must implement the same trait and response validation:

- local model runtime provider: deferred
- optional remote model provider: deferred and never required for acceptance

No future provider may bypass secret-handle rules, output bounds, cancellation,
timeout handling, tool validation, or fail-closed state mapping.
