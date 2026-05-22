# Runtime State Directory Permissions

Source task: `TASK-DALPHA-002`
Workflow: `WFS-20260523-agentos-distribution-alpha`
Input manifest: `.workflow/active/WFS-20260523-agentos-distribution-alpha/docs/rootfs-runtime-install-manifest.md`

## Purpose

Distribution Alpha must treat runtime state as an OS contract, not as incidental
application files. AgentCore recovery depends on persisted `PlanRun` state and
append-only audit evidence. After restart, `agentd` must reconcile durable
RunStore snapshots with AuditJournal truth and must never ask the model what
happened.

This document defines the rootfs directory contract for:

- `/var/lib/agentos/runs/`
- `/var/log/agentos/audit/`
- `/var/lib/agentos/rollback/`
- `/var/lib/agentos/memory/`

## Runtime Authority

Alpha uses `root:root` as the initial runtime authority because `agentd` is the
PID 1 control plane. Later tasks may introduce a dedicated `agentos` user, but
that requires an accepted decision and updates to this document, the rootfs
manifest, image validation, and release gates.

Initial permission rule:

```text
runtime-writable persistent state: owner=root:root, mode=0700
read-only package config: owner=root:root, mode=0644
runtime executable paths: owner=root:root, mode=0755
```

No runtime state directory may be world-writable or group-writable in normal
mode. Rescue/research modes, if introduced later, must be explicitly separated
from Alpha promotion gates.

## Directory Contract

| Artifact ID | Path | Owner | Mode | Persistence | Writer | Reader | Required validation |
|---|---|---|---|---|---|---|---|
| `state.runs` | `/var/lib/agentos/runs/` | `root:root` | `0700` | persistent across restart | `agentd` runtime only | `agentd`, recovery coordinator | exists; directory; mode; owner; restart-survives; no-secret-values; run-store-schema |
| `state.audit` | `/var/log/agentos/audit/` | `root:root` | `0700` | persistent across restart | `agentd` audit journal only | `agentd`, audit projection, recovery coordinator | exists; directory; mode; owner; restart-survives; append-only-intent; audit-projection; no-secret-values |
| `state.rollback` | `/var/lib/agentos/rollback/` | `root:root` | `0700` | persistent across restart | `agentd` rollback runtime only | `agentd`, recovery coordinator, final audit | exists; directory; mode; owner; restart-survives; rollback-handle-schema; no-secret-values |
| `state.memory` | `/var/lib/agentos/memory/` | `root:root` | `0700` | persistent across restart unless TTL expires | `agentd` memory runtime only | `agentd`, Planner context builder | exists; directory; mode; owner; restart-survives; ttl-aware; source-labeled; no-secret-values |

## State-Specific Rules

### `state.runs`

`/var/lib/agentos/runs/` stores persisted `PlanRun` state. It must contain
enough state to recover a run without model replay:

- `run_id`
- frozen plan hash
- current state
- current step cursor
- approval request or denial state
- observation references
- memory references
- recovery marker

Validation must reject:

- raw passwords, tokens, API keys, or private keys
- model prompts or raw model output used as recovery truth
- direct tool execution claims without audit references
- mutable plan state that no longer matches the frozen plan hash

Restart-survival check:

1. Create or stage a recoverable `PlanRun` marker.
2. Simulate restart by remounting/reopening the staged rootfs or booting QEMU.
3. Confirm the marker survives and is readable only by runtime authority.
4. Confirm recovery classification uses RunStore plus audit references.

### `state.audit`

`/var/log/agentos/audit/` is the append-only runtime evidence path. Alpha does
not need production-grade immutable storage yet, but it must preserve append-only
intent:

- `IntentReceived`, `PlanFrozen`, `PolicyEvaluated`, `ApprovalBound`,
  `EffectPrepared`, `EffectObserved`, `CommitSealed`, `RollbackPending`,
  `RollbackObserved`, `RecoveryStarted`, and `RecoveryCompleted` remain durable.
- Denied paths must write `PolicyEvaluated` but must not create
  `EffectPrepared`.
- Audit projection must read both latest run and explicit run ID timelines.

Validation must reject:

- raw secret values
- unredacted provider credentials
- unexplained effect state without run ID and step ID
- audit files that are writable by non-runtime users in normal mode

Restart-survival check:

1. Write or stage an audit timeline with at least one sealed read-only effect.
2. Reopen after restart simulation.
3. Run or define the projection check for latest run and explicit run ID.
4. Confirm event ordering is stable and secret redaction remains intact.

### `state.rollback`

`/var/lib/agentos/rollback/` stores rollback metadata and write-with-diff
handles. It is not a dump of secret-bearing file contents. Rollback metadata may
include hashes, target paths, previous/proposed content references, policy
version, and parameter hash.

Validation must reject:

- raw secret-bearing previous content
- rollback handles without parameter hash or policy version
- handles not linked to `EffectPrepared` / `RollbackPending` audit events
- rollback metadata writable by non-runtime users

Restart-survival check:

1. Stage a write-with-diff rollback handle.
2. Reopen after restart simulation.
3. Confirm recovery can classify the handle as rollback-required or
   human-review-required.
4. Confirm repeated rollback would be idempotent if `RollbackObserved` already
   exists.

### `state.memory`

`/var/lib/agentos/memory/` stores bounded memory entries. Memory is never policy
authority and never grants capability or approval. Planner-facing memory context
must be a bounded summary with source references, trust labels, TTL, redaction
status, policy flags, and integrity hash.

Validation must reject:

- raw secret values
- policy override claims as trusted memory
- approval-granted claims as trusted memory
- capability lease claims as trusted memory
- untrusted external content stored without source label or quarantine flag

Restart-survival check:

1. Stage safe run memory and quarantined untrusted memory.
2. Reopen after restart simulation.
3. Confirm safe memory remains bounded and source-labeled.
4. Confirm quarantined memory does not enter Planner context.
5. Confirm expired TTL entries are not treated as active context.

## Secret-Safety Validation

The Alpha validator should use a conservative content scan before promotion.
The scan is not the only security boundary, but it catches packaging mistakes.

Reject any state file containing obvious raw secret indicators:

- `password=`
- `passwd=`
- `api_key=`
- `apikey=`
- `access_token=`
- `refresh_token=`
- `private key`
- `BEGIN RSA PRIVATE KEY`
- `BEGIN OPENSSH PRIVATE KEY`

Allowed secret references must be handles or metadata only:

```text
secret://handle/...
secret_handle_id
redaction_status=redacted
```

If content is ambiguous, validation should fail closed and require human review
before Alpha promotion.

## Evidence Schema

`TASK-DALPHA-003` should emit permission evidence using this shape:

```json
{
  "schema": "agentos.runtime-state-permissions.v1",
  "rootfs": "path or image id",
  "checked_at": "ISO-8601 timestamp",
  "runtime_authority": "root:root",
  "directories": [
    {
      "artifact_id": "state.runs",
      "path": "/var/lib/agentos/runs/",
      "exists": true,
      "kind": "directory",
      "owner": "root:root",
      "mode": "0700",
      "writable_by_runtime_only": true,
      "restart_survives": true,
      "secret_scan": "passed",
      "checks": ["run-store-schema", "no-secret-values"]
    }
  ],
  "result": "passed"
}
```

On Windows-hosted development, an early validator may initially verify intended
owner/mode from a manifest projection. Before Alpha promotion, a Linux rootfs or
QEMU smoke must verify actual owner/mode behavior.

## Promotion Gates

Distribution Alpha promotion must fail if any of these are true:

- A required state directory is missing.
- A required state directory is world-writable or group-writable.
- Persistent state is stored only under a temporary path.
- Raw secret-like values appear in run, audit, rollback, or memory state.
- Audit projection cannot read latest and explicit run ID timelines.
- Recovery cannot classify unresolved effect state from RunStore plus
  AuditJournal.
- Memory quarantine can enter Planner context as authority.

## Handoff

- `TASK-DALPHA-003` consumes this document to implement rootfs staging and
  permission validation.
- `TASK-DALPHA-005` must include state directory entries in image assembly
  manifests.
- `TASK-DALPHA-006` uses `state.audit` and `state.runs` to prove packaged
  service recovery smoke.
- `TASK-DALPHA-008` records state permission evidence and rootfs manifest hashes
  in Alpha provenance.
- `TASK-DALPHA-012` uses this evidence to decide Alpha promotion or blocking
  risks.

## Completion Criteria

`TASK-DALPHA-002` is complete when the four persistent runtime paths are
specified with owner/mode, runtime authority, secret-safety, restart-survival,
audit projection, recovery, memory quarantine, and evidence schema requirements.
