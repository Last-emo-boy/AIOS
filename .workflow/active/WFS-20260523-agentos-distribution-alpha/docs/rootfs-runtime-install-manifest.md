# Rootfs Runtime Install Manifest

Source task: `TASK-DALPHA-001`
Workflow: `WFS-20260523-agentos-distribution-alpha`
Entry contract: `.workflow/active/WFS-20260522-agentos-runtime-foundation/docs/distribution-alpha-entry-criteria.md`

## Purpose

Distribution Alpha must install the completed Agent Core Runtime and Security
Execution Foundation into the future rootfs. A bootable image that only reaches
`/sbin/agentd` is not enough. Image assembly, QEMU smoke, and release promotion
must all validate this manifest before treating a build as an Alpha candidate.

The manifest contract is:

```text
runtime foundation evidence
  -> rootfs artifact manifest
  -> state/config validation
  -> runtime-aware image assembly
  -> QEMU runtime smoke
  -> release provenance and promotion gate
```

## Manifest Schema

Future automation should emit a stable JSON document with this top-level shape:

```json
{
  "schema": "agentos.rootfs-runtime-manifest.v1",
  "generated_at": "ISO-8601 timestamp",
  "source_revision": "git commit or null",
  "runtime_contract": {
    "requires_runtime_foundation_final_audit": "TASK-RTF-005",
    "requires_security_execution_final_verification": "TASK-SEF-010",
    "requires_generic_service_recovery": "TASK-ACR-009"
  },
  "artifacts": [
    {
      "id": "agentd.boot",
      "kind": "executable",
      "path": "/sbin/agentd",
      "owner": "root:root",
      "mode": "0755",
      "persistence": "boot-critical",
      "required_hash": true,
      "secret_policy": "no-secret-values",
      "validation": ["exists", "executable", "sha256", "handoff-marker"]
    }
  ]
}
```

Each artifact entry must include:

| Field | Meaning |
|---|---|
| `id` | Stable identifier used by validation, image assembly, QEMU smoke, and provenance. |
| `kind` | One of `executable`, `config`, `manifest`, `directory`, or `metadata`. |
| `path` | Rootfs absolute path. |
| `owner` | Initial Alpha owner contract. `root:root` is the default runtime authority for PID 1 Alpha. |
| `mode` | Required permission intent. Later Linux validation should check it directly. |
| `persistence` | `boot-critical`, `persistent-state`, `read-only-config`, or `release-metadata`. |
| `required_hash` | Whether release provenance must include a content hash. Directories may hash their manifest projection. |
| `secret_policy` | Always `no-secret-values` or `handle-metadata-only`. |
| `validation` | Stable validation labels consumed by `TASK-DALPHA-003` and later gates. |

## Required Artifacts

| ID | Kind | Rootfs path | Owner | Mode | Persistence | Required validation | Source proof | Consumed by |
|---|---|---|---|---|---|---|---|---|
| `agentd.boot` | executable | `/sbin/agentd` | `root:root` | `0755` | `boot-critical` | exists; executable; sha256; boot emits `AGENTD_HANDOFF_OK` or accepted equivalent | `TASK-AIOS-001`, `TASK-RTF-005` | image assembly, QEMU boot smoke |
| `agentd.runtime` | executable | `/usr/lib/agentos/agentd` | `root:root` | `0755` | `boot-critical` | exists; executable; sha256; AgentCore commands available; same build provenance as boot path or documented wrapper relation | `TASK-ACR-005`, `TASK-SEF-010`, `TASK-RTF-005` | packaged service recovery, provenance |
| `policy.pack` | config | `/etc/agentos/policy/policy-pack.json` | `root:root` | `0644` | `read-only-config` | policy version present; exact approval binding; high-risk pause rules; denied normal-mode shell; sha256 | `TASK-AIOS-007`, `TASK-SEF-002`, `TASK-SEF-008` | config packaging, state validation, service recovery smoke |
| `tools.semantic` | manifest | `/etc/agentos/tools/semantic-tools.json` | `root:root` | `0644` | `read-only-config` | includes allowed semantic tools; excludes normal-mode `shell.exec`; schema version; sha256 | `TASK-AIOS-004`, `TASK-SEF-002`, `TASK-SEF-004` | config packaging, image assembly, release provenance |
| `model_broker.config` | config | `/etc/agentos/model-broker.toml` | `root:root` | `0644` | `read-only-config` | stub/local-only provider is default; remote providers optional and disabled unless explicitly configured; no raw credentials; sha256 | `TASK-ACR-003`, `TASK-ACR-004`, `TASK-RTF-005` | config packaging, service recovery smoke, release provenance |
| `state.runs` | directory | `/var/lib/agentos/runs/` | `root:root` | `0700` | `persistent-state` | directory exists; writable by runtime authority only; survives restart; contains no raw secrets; supports PlanRun snapshots | `TASK-ACR-002`, `TASK-ACR-005`, `TASK-SEF-007` | state permission validation, recovery smoke |
| `state.audit` | directory | `/var/log/agentos/audit/` | `root:root` | `0700` | `persistent-state` | directory exists; append-only journal path available; runtime audit projection can read latest and explicit run IDs; contains no raw secrets | `TASK-AIOS-005`, `TASK-SEF-009`, `TASK-RTF-005` | audit projection, service recovery smoke, provenance |
| `state.rollback` | directory | `/var/lib/agentos/rollback/` | `root:root` | `0700` | `persistent-state` | directory exists; rollback handles persist; write-with-diff handles classify after restart; contains hashes and paths, not secret values | `TASK-AIOS-009`, `TASK-SEF-001`, `TASK-SEF-007` | state validation, package install isolation, release audit |
| `state.memory` | directory | `/var/lib/agentos/memory/` | `root:root` | `0700` | `persistent-state` | directory exists; entries are bounded, source-labeled, TTL-aware, redacted, and secret-safe | `TASK-ACR-008`, `TASK-ACR-010`, `TASK-SEF-008` | state validation, adversarial tests, untrusted content workflow |
| `release.provenance` | metadata | `/usr/lib/agentos/release/provenance.json` | `root:root` | `0644` | `release-metadata` | records source revision, toolchain, dependency inventory, artifact hashes, gate commands, image inputs, and rootfs manifest hash; no raw secrets | `TASK-AIOS-012`, `TASK-RTF-005` | Alpha promotion gate |
| `release.rootfs_manifest` | metadata | `/usr/lib/agentos/release/rootfs-runtime-manifest.json` | `root:root` | `0644` | `release-metadata` | contains this manifest projection; sha256 recorded in provenance; validates before promotion | `TASK-DALPHA-001` | image assembly, QEMU smoke, final audit |

## Artifact Rules

### agentd boot and runtime paths

`/sbin/agentd` remains the boot handoff path for QEMU smoke. The managed
runtime path is `/usr/lib/agentos/agentd`. Alpha automation may implement the
boot path as a hard link, copy, or wrapper to the managed runtime binary, but
the manifest must record the relationship and hash both paths or the canonical
target. A path change requires an accepted decision that updates this document,
`TASK.md`, the Alpha tasks, and release gates.

### Policy pack

The policy pack must preserve the existing capability policy:

- `read-only` can allow without approval.
- `write-with-diff`, `execute-with-confirmation`, and
  `privileged-with-human-approval` pause without exact approval.
- `never` is denied even with approval.
- Approval tokens bind actor, tool, resource, parameter hash, expiry, and policy
  version.

Broad session approval is forbidden. Denied decisions must still be auditable
and must not create `EffectPrepared`.

### Semantic tool manifest

The semantic tool manifest must include only typed semantic tools known to the
runtime. Initial Alpha must include the MVP/runtime tool set:

- `svc.logs`
- `svc.status`
- `http.check`
- `config.test`
- `fs.read`
- `fs.write.diff`
- `svc.restart`
- `audit.show`
- `rollback.trigger`

Normal-mode `shell.exec` must be absent from the manifest and explicitly denied
by policy.

### ModelBroker config

`/etc/agentos/model-broker.toml` must default to stub/local-only mode. External
providers are optional and cannot be required by boot smoke, release promotion,
service recovery, offline recovery, or acceptance tests.

Minimum config intent:

```toml
[model_broker]
mode = "stub"
network_required = false
default_provider = "stub-local"

[providers.stub-local]
kind = "stub"
enabled = true
requires_credentials = false
```

Provider metadata may be logged. Raw prompts, raw observations, raw secrets,
tokens, passwords, and provider credentials must not appear in config,
provenance, audit, memory, or model call logs.

## Validation Labels

`TASK-DALPHA-003` should use these validation labels when it implements the
rootfs validator:

| Label | Meaning |
|---|---|
| `exists` | Path exists in the staged rootfs. |
| `directory` | Path is a directory. |
| `file` | Path is a regular file. |
| `executable` | Executable bit is present for runtime authority. |
| `mode` | Permission intent matches manifest. |
| `owner` | Owner intent matches manifest where the build host can verify it. |
| `sha256` | File content hash is recorded. |
| `no-secret-values` | Content scan rejects obvious secret-like values. |
| `handle-metadata-only` | Secret references are handles or metadata only. |
| `offline-model-mode` | ModelBroker default does not require network or credentials. |
| `denied-shell` | Normal-mode `shell.exec` is absent or explicitly denied. |
| `runtime-command` | Packaged runtime exposes AgentCore smoke or equivalent command. |
| `handoff-marker` | QEMU smoke observes `AGENTD_HANDOFF_OK` or accepted equivalent. |
| `audit-projection` | Runtime audit projection can read latest and explicit run IDs. |
| `restart-survives` | Directory state persists across restart or staged restart simulation. |

## Handoff

- `TASK-DALPHA-002` consumes `state.runs`, `state.audit`, `state.rollback`, and
  `state.memory` for permission and restart-survival validation.
- `TASK-DALPHA-003` consumes every artifact ID and validation label to implement
  a fail-closed rootfs staging validator.
- `TASK-DALPHA-004` consumes `policy.pack`, `tools.semantic`, and
  `model_broker.config` for packageable runtime defaults.
- `TASK-DALPHA-005` consumes `release.rootfs_manifest` during runtime-aware
  image assembly.
- `TASK-DALPHA-006` consumes `agentd.runtime`, `policy.pack`, `tools.semantic`,
  `model_broker.config`, and `state.audit` for packaged service recovery smoke.
- `TASK-DALPHA-008` consumes `release.provenance` and
  `release.rootfs_manifest` for Alpha promotion.

## Completion Criteria

`TASK-DALPHA-001` is complete when this document exists, covers every mandatory
runtime artifact from the Alpha entry criteria, distinguishes boot and runtime
`agentd` paths, requires stub/local-only ModelBroker acceptance, forbids raw
secret values, forbids normal-mode `shell.exec`, and provides stable fields for
later validator automation.
