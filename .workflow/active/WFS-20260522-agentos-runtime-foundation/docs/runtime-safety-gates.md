# Runtime Safety Gates

Source: `TASK.md:139`
Task: `TASK-RTF-003`
Workflow: `WFS-20260522-agentos-runtime-foundation`

## Purpose

This document carries the completed Linux MVP safety invariants forward into
Runtime Foundation execution. AgentCore adds autonomy pressure, so these gates
are stricter than the MVP gates: every runtime task must preserve the existing
security substrate and add coverage for model output, observations, memory, and
approval pauses.

## MVP Invariants That Remain Mandatory

| Invariant | Existing evidence / test family | Runtime requirement |
|---|---|---|
| Normal mode denies arbitrary shell. | `lifecycle::tests::denies_arbitrary_shell_in_normal_mode`, `tools::tests::rejects_shell_exec_and_unknown_tools` | AgentCore must not introduce a planner, CLI, TUI, or recovery path that can call raw shell. |
| Semantic tools are the only effect surface. | `tools::tests::*`, `policy::tests::*` | PlanStep execution must route through `ToolRouter` before policy. |
| High-risk actions require exact approval. | `policy::tests::approval_token_must_match_exact_parameter_hash`, `safety::tests::broad_approval_token_cannot_authorize_changed_parameters` | AwaitingApproval denial or timeout must produce no `EffectPrepared`. |
| Denied actions are audited without execution. | `policy::tests::records_denied_decision_without_executing`, `safety::tests::denied_actions_are_audited_without_effect_prepared` | Runtime denied states must preserve decision evidence and never prepare protected effects. |
| Read-only tools are sandboxed and non-persistent. | `sandbox::tests::*`, `safety::tests::resource_abuse_hits_configured_sandbox_limits` | Runtime read-only steps must receive lease-derived sandbox profiles. |
| Writes require diff and rollback handle. | `rollback::tests::*` | AgentCore write steps must use `fs.write.diff` semantics and cannot commit without verification. |
| Recovery reconciles unfinished effects. | `recovery::tests::*`, `safety::tests::rollback_failure_tests_cover_stale_base_and_half_committed_effect` | Restart must use RunStore plus AuditJournal; model replay is not recovery truth. |
| Secret values are handle-only. | `audit::tests::redacts_secret_like_summary_tokens`, `safety::tests::secret_values_are_redacted_but_handles_remain_visible` | ModelBroker, MemoryStore, ObservationProcessor, audit projection, and TUI must preserve handle-only behavior. |
| Prompt injection fails closed. | `safety::tests::prompt_injection_fixtures_cannot_prepare_side_effects` | External content and observations cannot directly create high-risk tool calls. |
| Release artifacts carry provenance. | `scripts/build-release.ps1` | Runtime release readiness requires old MVP release checks plus AgentCore gates. |

## Existing Safety Scenarios

The existing `crates/agentd/src/safety.rs` gate declares these mandatory MVP
scenarios:

```text
prompt-injection-shell
prompt-injection-exfiltration
prompt-injection-login-download
prompt-injection-policy-override
never-class-tool-abuse
broad-approval-rejected
secret-handle-only-redaction
resource-fork-bomb
resource-denied-syscall
rollback-stale-base
recovery-half-committed-effect
```

These scenarios stay mandatory for every Runtime Foundation wave.

## Runtime-Specific Gate Additions

The implementation tasks must add or prove coverage for these scenarios:

| Runtime scenario | Required by | Failure condition |
|---|---|---|
| `model-output-shell-command` | `TASK-ACR-003`, `TASK-ACR-004`, `TASK-ACR-010` | Model output containing shell commands becomes a tool call or effect. |
| `model-output-unknown-tool` | `TASK-ACR-004`, `TASK-SEF-002` | Planner freezes an unknown or unrouted tool. |
| `observation-injection-command` | `TASK-ACR-007`, `TASK-SEF-004`, `TASK-ACR-010` | Tool output or external content directly schedules high-risk action. |
| `observation-secret-redaction` | `TASK-ACR-007`, `TASK-SEF-005` | Observation text leaks raw secret values into memory, model context, audit, or TUI. |
| `memory-poisoning-policy-override` | `TASK-ACR-008`, `TASK-ACR-010` | Memory entry changes policy, grants capability, or weakens approval. |
| `memory-secret-retention` | `TASK-ACR-008`, `TASK-SEF-005` | Memory persists password/token/key-like values as normal entries. |
| `approval-timeout-no-effect` | `TASK-ACR-005`, `TASK-SEF-002` | Timeout or denial emits `EffectPrepared` for protected step. |
| `runstore-recovery-half-step` | `TASK-ACR-002`, `TASK-SEF-007` | Crash after prepare/observe cannot be classified from durable state. |
| `planner-risk-hint-downgrade` | `TASK-ACR-004`, `TASK-SEF-002` | Planner marks high-risk action read-only and policy accepts the downgrade. |
| `agentcore-bypass-security-engine` | `TASK-ACR-005`, `TASK-SEF-006`, `TASK-SEF-010` | AgentCore executes effect without SecurityExecutionEngine. |

## Regression Commands

Each Runtime Foundation wave must pass the relevant command set before tasks in
that wave can be marked completed.

| Wave | Required commands |
|---|---|
| Wave 0 boundary tasks | `cargo test -p agentd`; `cargo test -p agentd safety::`; JSON parse of `.workflow/**/*.json`. |
| Wave 1 Agent Core contracts | `cargo test -p agentd`; `cargo test -p agentd safety::`; targeted tests for `agent_core::model`, `agent_core::run_store`, `model_broker::`, and `planner::` as they are introduced. |
| Wave 2 SEF hardening | `cargo test -p agentd`; `cargo test -p agentd safety::`; targeted tests for `security_execution::effect_envelope`, `security_execution::policy_adapter`, source-to-sink policy, and secret handling. |
| Wave 3 generic run loop | `cargo test -p agentd`; `cargo test -p agentd safety::`; `cargo test -p agentd agent_core::`; targeted recovery and execution bridge tests. |
| Wave 4 migration and gates | `cargo test -p agentd`; `cargo test -p agentd safety::`; `cargo test -p agentd agent_core::`; approved and denied service recovery demos; release pipeline where changed. |
| Wave 5 final audit | Full test suite, safety subset, AgentCore subset, release pipeline, optional QEMU boot smoke if boot artifacts changed, and clean tracked git status. |

## Completion Rules

A task cannot be completed if it:

- Adds any direct model-to-tool path.
- Adds any planner-to-shell path.
- Executes a side effect outside SecurityExecutionEngine.
- Creates a second policy engine, audit journal, tool router, rollback manager,
  or recovery reconciler.
- Stores raw secret values in model context, memory, audit summaries, or TUI.
- Lets untrusted content or observations directly trigger high-risk sinks.
- Marks a denied or timed-out approval as prepared.
- Uses model replay as recovery truth.

## Baseline Verification

Before Runtime Foundation implementation starts:

```text
cargo test -p agentd
  49 passed; 0 failed

cargo test -p agentd safety::
  8 passed; 0 failed
```

These commands were run for `TASK-RTF-003` and are recorded in the evidence
file for the task.
