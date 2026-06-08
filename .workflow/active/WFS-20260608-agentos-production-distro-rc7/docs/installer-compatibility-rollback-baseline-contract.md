# Installer Compatibility And Rollback Baseline Publication Contract

## Scope

RC7-003 closes the contract gap left by RC6 bootstrap preflight and RC6 rollback precondition evidence. RC6 proved that hosted payload metadata can be fetched and verified as a candidate, but install remained blocked on four gates: public signature or signed metadata, revocation snapshot, installer compatibility contract, and rollback baseline hash. RC7-002 now publishes signed metadata and revocation projection while still keeping the payload `verification-blocked`.

This contract defines the two remaining install metadata gates:

- `/install/compatibility.json`: target and installer compatibility contract.
- `/install/rollback-baseline.json`: rollback baseline publication contract.

Publishing these documents does not authorize install, activation, canary execution, rollback execution, active slot mutation, boot metadata mutation, production ring mutation, support upload, remote dispatch, model authority, shell authority, or TUI authority.

## Compatibility Contract

The compatibility document must be public metadata with this shape:

- `schema`: `agentos.rc7-installer-compatibility.v1`.
- `release_id`: current payload release id.
- `status`: `compatibility-projected-verification-blocked` until install evidence exists.
- `target_arch`: supported CPU architecture list.
- `image_format`: supported image or rootfs format list.
- `boot_path`: expected boot mode, initramfs contract, kernel family, and console readiness marker.
- `minimum_runtime`: minimum `agentd`, AgentCore, SecurityExecutionEngine, and installer contract versions.
- `required_metadata`: payload index, manifest, checksums, signatures, signed metadata, revocation snapshot, rollback baseline, support/recovery metadata, and release provenance hashes.
- `drift_policy`: declared/current hash drift must block install until reconciled.
- `storage_policy`: large payload storage must remain blocked until object storage policy exists.
- `authority`: mirror, signer, installer preflight, frontend, TUI, model replay, and normal shell are not activation authorities.

The installer may only move from `verification-blocked` to `signed-consumption-ready` when this compatibility contract is present, hash-bound from `/install/bootstrap.json`, and locally matched against the target machine profile.

## Compatibility Match Inputs

An installer compatibility decision must bind:

- Release id and payload manifest hash.
- Payload checksums hash.
- Signed metadata hash.
- Revocation snapshot hash.
- Compatibility contract hash.
- Rollback baseline hash.
- Target architecture and boot mode.
- Rootfs/initramfs contract hash when present.
- Minimum runtime component versions.
- Freshness window and policy version.
- Operator-visible explanation of every mismatch.

Compatibility mismatch is not recoverable by operator approval alone. It requires new metadata or a new payload candidate.

## Rollback Baseline Contract

The rollback baseline document must be public metadata with this shape:

- `schema`: `agentos.rc7-rollback-baseline.v1`.
- `release_id`: current payload release id.
- `status`: `rollback-baseline-projected-execution-blocked` until exact-approved rollback drill evidence exists.
- `rollback_baseline_sha256`: baseline hash already proven by RC4, RC5, and RC6 rollback readiness evidence.
- `previous_active_artifact_set_sha256`: the active artifact set that rollback would restore.
- `restored_active_artifact_set_sha256`: the expected restored artifact set hash.
- `support_recovery_binding`: support/recovery metadata hash and operation id.
- `security_execution_requirement`: SecurityExecutionEngine PlanSpec approval requirement.
- `operator_approval_requirement`: exact actor, target, release id, payload digest, expiry, and policy version.
- `execution_status`: rollback execution remains false.

The rollback baseline proves that the candidate has an auditable recovery target. It does not execute rollback.

## Publication Rules

RC7 publication tasks may add:

- `/install/compatibility.json`
- `/install/rollback-baseline.json`
- matching hash references under `/install/bootstrap.json`
- matching hash references under `/payloads/index.json`
- optional mirror frontend display of compatibility and rollback status

The following must remain false after publication:

- `install_allowed`
- `activation_allowed`
- `rollback_execution_allowed`
- `canary_execution_allowed`
- `production_ready_claim`
- `signing_authority_on_mirror`
- `remote_dispatch_enabled`
- `tui_authority`

## State Transitions

Allowed RC7 states:

- `metadata-observed`: metadata fetched and parsed.
- `hash-bound`: manifest, checksums, provenance, signed metadata, and revocation bindings verify.
- `compatibility-projected`: compatibility contract exists and is hash-bound.
- `compatibility-matched`: local target profile matches the compatibility contract.
- `rollback-baseline-bound`: rollback baseline exists and is hash-bound.
- `signed-consumption-ready`: all metadata gates verify, but install is still awaiting explicit policy and operator gate.
- `controlled-execution-ready`: exact-approved AgentCore PlanSpec and SecurityExecutionEngine ownership exist for canary or rollback.
- `verification-blocked`: any missing or mismatched input blocks install and execution.

RC7-003 only defines the contract. It does not move the current payload out of `verification-blocked`.

## Fail-Closed Cases

Installer consumption and rollback publication must fail closed for:

- Missing compatibility contract.
- Compatibility schema mismatch.
- Target architecture mismatch.
- Boot path mismatch.
- Runtime version below minimum.
- Missing payload manifest, checksums, signed metadata, revocation, or rollback baseline hash.
- Hash mismatch between `/install/bootstrap.json` and the compatibility or rollback baseline documents.
- Missing support/recovery binding.
- Rollback baseline hash mismatch.
- Previous/restored active artifact set mismatch.
- Declared/current payload hash drift.
- Large payload URL before storage policy and object storage boundary.
- TLS evidence missing before GA claim.
- Any install, activation, rollback, remote dispatch, support upload, production ring mutation, TUI, shell, or model authority broadening.

## Next Evidence

RC7-010 should project installer signed metadata consumption using this contract. It should demonstrate that the installer can see signed metadata projection and revocation projection, while still reporting `verification-blocked` until compatibility and rollback baseline documents are published and hash-bound.

RC7-012 should publish the rollback baseline metadata projection after RC7-010 and RC7-011 prove the consumption and fail-closed behavior.
