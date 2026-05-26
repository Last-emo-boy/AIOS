# Organization Policy Overlay Preview

## Status

This is a Console Beta design document. Organization policy overlays are preview-only until a future implementation task is approved.

The baseline local policy remains authoritative. An organization overlay may add restrictions, labels, allowlists, denylists, mirror pins or approval requirements. It may not remove local AgentOS safety invariants or make remote policy stronger than local enforcement.

## Non-Removable Core Invariants

The following invariants are non-removable:

- `no-shell`
- `exact-approval`
- `secret-handle`
- `source-to-sink`
- `audit`
- `rollback`

An overlay that attempts to disable, rename away, downgrade or bypass any of these invariants must be projected as `incompatible` or `revoked` and must block activation preview.

## Overlay States

The TUI should project overlays with explicit states:

- `absent`: no organization overlay is configured; baseline local policy remains active.
- `compatible`: overlay is signed, not revoked and preserves all core invariants.
- `stricter`: overlay adds restrictions such as narrower channels, allowlists, denied publishers, extra approvals or shorter expiry.
- `incompatible`: overlay broadens authority or conflicts with local core invariants.
- `unsigned`: overlay has no valid detached signature or no trusted signing key.
- `revoked`: overlay id, signer, publisher or policy version is revoked.

Only `compatible` and `stricter` may be eligible for future activation preview. `unsigned`, `revoked` and `incompatible` are blockers.

## Policy Diff UX

The preview should show policy diff groups:

- `added_restrictions`: new deny rules, narrowed trust tiers, disallowed channels, stricter quotas, shorter approval expiry or extra replay gates.
- `removed_restrictions`: any removed deny rule or broader allowed scope.
- `authority_broadening`: new tool, sink, publisher, channel, host path, network target, package source or model provider authority.
- `invariant_changes`: attempted changes to no-shell, exact approval, secret handle, source-to-sink, audit or rollback.
- `approval_changes`: changes to actor, expiry, risk class, parameter hash binding, policy version or escalation.
- `rollback_changes`: changes to rollback handle requirements or rollback preservation evidence.

Added restrictions are safe to preview as `stricter` if they validate. Removed restrictions and authority broadening are never silently accepted. They require explicit future approval and runtime mediation, and they remain blocked in Console Beta unless a future implementation task defines an approved migration flow.

## Broadening Rules

Policy broadening includes:

- allowing normal shell or shell-like commands
- weakening exact approval binding
- allowing raw secret values instead of secret handles
- allowing untrusted/model-origin content to drive high-risk sinks
- making audit optional or remote-only
- removing rollback handles
- widening host filesystem writes
- adding network egress destinations
- allowing direct package manager use
- allowing direct activation without AgentCore PlanSpec
- allowing side effects outside SecurityExecutionEngine

Any broadening must be shown as `authority_broadening=true`, `runtime_mediation_required=true` and `activation_blocked=true` in preview.

## Activation Preview

Overlay activation must be previewed before any execution exists.

Future activation flow:

1. Load overlay from local pinned snapshot or trusted mirror result.
2. Verify overlay schema, detached signature, signer allowlist and revocation state.
3. Diff overlay against baseline local policy.
4. Reject invariant weakening before approval.
5. Build an AgentCore PlanRun for activation preview.
6. Bind exact approval to overlay id, overlay hash, signer, diff hash, actor, policy version and expiry.
7. Stage overlay inertly.
8. Run policy replay and ecosystem replay against the staged overlay.
9. Commit only through SecurityExecutionEngine.
10. Preserve rollback evidence for the previous local policy set.

Console Beta implements only the design/projection part of this flow. There is no direct overlay activation command.

## Approval Requirements

Any future overlay approval must bind:

- overlay id
- overlay content hash
- signer key id
- revocation snapshot hash
- baseline policy hash
- policy diff hash
- actor
- approval expiry
- target node or fleet label
- rollback handle id

Changing the overlay, signer, diff, target, baseline policy or rollback handle invalidates approval.

## Audit And Rollback Expectations

Preview should identify the evidence a future activation must emit:

- `OverlayLoaded`
- `OverlaySignatureVerified`
- `OverlayDiffEvaluated`
- `PolicyEvaluated`
- `ApprovalBound`
- `EffectPrepared`
- `EffectObserved`
- `CommitSealed`
- `RollbackHandleRecorded`

Rollback must restore the previous local policy set and its hash. Recovery must use local RunStore plus AuditJournal, not model replay or remote policy replay.

## TUI Boundary

The TUI may render overlay state, signer status, diff groups, blockers, safe next actions and future approval requirements. It may not:

- activate overlays
- sign overlays
- clear overlay blockers
- mutate local policy files
- weaken local invariants
- make remote organization policy authoritative
- bypass AgentCore, SecurityExecutionEngine or AOM resolver rules

All executable overlay work must stay outside the display layer.

## Operator Copy Rules

Use precise status text:

- `preview-only`
- `activation_blocked=true`
- `local_invariants_preserved=true`
- `unsigned_blocked=true`
- `revoked_blocked=true`
- `runtime_mediation_required=true`

Avoid `ready` unless scoped as `preview-compatible`. Never use `production-ready` for an overlay preview.

## Evidence Required Before Implementation

Before overlay execution exists, RC0 needs:

- overlay schema and signature fixtures
- unsigned and revoked overlay replay fixtures
- policy diff tests for stricter, compatible, broadening and invariant weakening overlays
- approval mutation tests for overlay hash and diff hash
- rollback drill restoring previous policy set
- support bundle fields explaining overlay state
- TUI projection tests showing unsigned/revoked/incompatible blockers

## Non-Goals

- No overlay execution in Console Beta.
- No disabling no-shell or exact approval.
- No remote override of local policy.
- No unsigned overlay compatibility claim.
- No hidden approval for policy broadening.
