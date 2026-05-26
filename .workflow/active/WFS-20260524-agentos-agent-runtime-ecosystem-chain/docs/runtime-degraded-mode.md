# Runtime Degraded Mode And Local Fallback

Task: `TASK-ARUN-013`

## Purpose

AgentOS depends on Agent Runtime to operate the OS. Production Distro behavior must therefore be explicit when optional dependencies are missing: the system should keep local operation, diagnostics, projection and safe recovery available, while blocking or suspending capabilities that cannot satisfy their authority, isolation or verification requirements.

Degraded mode is a reduction in capability, not an expansion of authority.

## Existing Runtime Basis

Current implementation already establishes the baseline:

- `docs/model-broker.md` states that `ModelBroker` is the only model access boundary and that model failures cannot execute tools.
- `packaging/agentos/rootfs/etc/agentos/model-broker.toml` defaults to `mode = "stub"`, `network_required = false`, `default_provider = "stub-local"` and disables the remote provider.
- `StubModelProvider` is deterministic, local-only and validates through the same `ModelBroker` boundary as future providers.
- The functional capability matrix states that external LLM, network, Firecracker and host package manager integrations are optional for baseline replay.
- SecurityExecution Firecracker profiles explicitly forbid host fallback when microVM dependencies are missing.

## Degraded Mode Classes

| Class | Missing or impaired dependency | Allowed baseline behavior | Blocked behavior |
| --- | --- | --- | --- |
| `model-remote-unavailable` | remote LLM, credentials or network | use local/stub `ModelBroker`; deterministic planning and summaries remain available | remote-only planning, raw prompt logging, model-direct tool execution |
| `network-unavailable` | outbound network, registry or external content fetch | local fixtures, cached/pinned snapshots, static content inspection | live fetch, remote registry refresh, unpinned activation |
| `microvm-unavailable` | Firecracker, jailer, KVM, kernel image or rootfs image | read-only diagnostics; explain missing isolation | high-risk effect profile that requires microVM; host fallback |
| `host-package-manager-unavailable` | `apt`, `dpkg` or host package integration | isolated/local metadata fixtures and explanation | host package mutation, maintainer scripts, implicit install |
| `adapter-unavailable` | runtime adapter binary/config missing | projection marks capability unavailable; dependent workflow pauses | direct shell or agentd-owned adapter substitute |
| `remote-audit-unavailable` | remote audit mirror or support upload | local audit hash chain and local support bundle remain available | treating remote mirror failure as reason to skip local audit |
| `registry-unavailable` | remote ecosystem registry unavailable | pinned local registry snapshot and lockfile checks | unpinned search/activation or install-as-activation |

## Local And Stub Fallback Rules

### ModelBroker

AgentOS must boot and run baseline workflows with:

```toml
mode = "stub"
network_required = false
default_provider = "stub-local"
```

Rules:

- remote provider is optional and disabled by default;
- provider failure, timeout, malformed output, oversized output or secret-like input maps to `Suspended` or `FailedClosed`;
- model output never grants approval, capability lease or policy override;
- fallback to stub does not reset budgets, approvals or replay evidence;
- raw prompt and raw observation logging stay disabled.

### Network

Network absence keeps local-only operation available:

- boot;
- operator projection;
- local/stub planning;
- local audit;
- local support bundle generation;
- local registry fixture or pinned snapshot checks;
- functional replay.

Network absence blocks live fetches and remote registry refresh. It must not cause the system to invent data or treat stale unpinned data as trusted.

### Firecracker And Isolation

If a capability requires microVM isolation, missing Firecracker dependencies fail closed before `EffectPrepared`.

Allowed fallback:

- read-only diagnostics;
- dependency probe;
- operator explanation;
- support bundle section.

Forbidden fallback:

- run the same high-risk effect on the host;
- downgrade risk class;
- grant writable host paths based on planner hints.

### Host Package Manager

Host package manager integration is optional. If unavailable:

- package metadata fixture workflows may remain read-only;
- isolated install smoke may be skipped or marked degraded if its dependencies are missing;
- host promotion must be blocked before mutation.

No degraded path may run `apt`, `dpkg`, shell, maintainer scripts or host promotion without exact approval, digest binding, rollback id and SecurityExecution mediation.

## Degraded Capability Matrix

| Capability | Normal path | Degraded path | Authority result |
| --- | --- | --- | --- |
| Boot/runtime ready | local packaged artifacts | same | allowed |
| Operator projection | local state and audit | same plus degraded reason | allowed |
| Read-only service diagnostics | sandboxed semantic tools | local fixtures or limited probes | allowed with quotas |
| Service restart | SecurityExecution with approval | pause when required dependency missing | awaiting approval or suspended |
| External content inspection | fetch then sanitize | static/file fixture only | read-only, untrusted |
| Package install | isolated validation then host promotion | metadata/explain only | host mutation blocked |
| Firecracker execution | microVM profile | dependency probe only | fail closed before effect |
| Ecosystem registry | pinned/verified snapshot | local pinned snapshot only | activation blocked if unverifiable |
| Support bundle | local bundle plus optional upload | local bundle only | allowed without secrets |
| Remote model planning | optional provider | stub/local provider | allowed only through ModelBroker |

## Projection Requirements

Operator projection should expose degraded state without secrets:

- `degraded.active`
- `degraded.class`
- `degraded.missing_dependencies`
- `degraded.capabilities_limited`
- `degraded.blocked_effects`
- `degraded.fallback_provider`
- `degraded.next_operator_action`
- `degraded.support_bundle_hint`

Projection is read-only. It explains state; it does not authorize action.

## Failure State Mapping

| Failure | Required state |
| --- | --- |
| Optional model timeout or cancellation | `Suspended` when retry/operator action can help |
| Malformed model output or secret-like model input | `FailedClosed` |
| Missing microVM dependency for high-risk effect | `FailedClosed` before `EffectPrepared` |
| Missing host package manager for host mutation | `Suspended` or `FailedClosed` before mutation |
| Network unavailable for live content fetch | `Suspended` or read-only fixture mode |
| Registry snapshot unavailable or unverifiable | activation blocked |
| Adapter unavailable | capability unavailable; no agentd substitute |

## Safety Invariants

- Baseline boot and functional replay remain local-only.
- Degraded mode never broadens authority.
- Missing optional dependencies never trigger host mutation.
- Missing isolation never falls back to direct host execution.
- Remote model is never required for acceptance.
- Stub fallback stays inside `ModelBroker`.
- Degraded projection must explain why a capability is limited.
- Any blocked side effect must happen before `EffectPrepared`.

## Verification Mapping

| Requirement | Current evidence |
| --- | --- |
| Baseline replay is local-only | `scripts/functional-capability-replay.ps1` |
| Stub model provider needs no network | `agent_core::model_broker::tests::stub_provider_plans_without_network_or_effects` |
| Model failures cannot execute tools | `agent_core::model_broker` failure tests and planner validation tests |
| Missing Firecracker deps have no host fallback | `security_execution` Firecracker dependency tests |
| Host package manager is optional and gated | functional package install and safety tests |

## Follow-Up Tasks

- `TASK-ARUN-020` should reconcile degraded state after boot from durable run, audit and active artifact state.
- `TASK-ECO-003` should ensure staged ecosystem artifacts record dependency and verification status without activation.
- `TASK-VERIFY-041` should include degraded-mode replay in ecosystem replay.
- `TASK-PROD-052` should turn pinned snapshot and offline operation into long-running production drills.
