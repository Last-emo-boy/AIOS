# Hosted Release Transport And Fleet Boundary

## Scope

RC4 starts from the RC3 final audit: production signatures verify, the local release channel is immutable and append-only, signed channel consumption passes, support/recovery projection is redacted, and the signing/publication gate is integrated. RC4 extends that proof into hosted transport and staged fleet operations without changing the authority model.

This contract covers:

- Hosted release transport metadata for a signed RC3 publication.
- Remote registry mirror replay and freshness evidence.
- Fleet-ring rollout planning for staged promotion.
- Support and recovery evidence needed to explain hosted or fleet failures.

This contract does not grant GA production readiness. It defines the evidence required before later RC4 implementation tasks may write hosted transport, mirror, fleet, or promotion artifacts.

## Authority Boundary

Hosted transport is distribution evidence only. It may expose content-addressed metadata, mirror snapshots, and signed indexes, but it may not activate a release, mutate an active slot, or rewrite an existing immutable channel head.

Fleet rollout is a plan-and-proof workflow:

- AgentCore owns rollout PlanSpec construction.
- SecurityExecutionEngine owns all side effects.
- TUI is projection-controller only.
- Model output may summarize or classify state, but may not authorize rollout or rollback.
- Normal shell and remote control-plane dispatch cannot satisfy rollout authority.

Every hosted or fleet artifact must preserve the RC3 constraints:

- No local private production signing material.
- No candidate signature substitution.
- No unsigned or revoked mirror artifact promotion.
- No in-place mutation of content-addressed publication metadata.
- No activation without exact operator approval and rollback evidence.

## Required Inputs

RC4 hosted transport evidence must bind these RC3 inputs:

- `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/FINAL-AUDIT-20260531-production-distro-rc3.json`
- `.workflow/artifacts/rc3-production-signature-verification/result.json`
- `.workflow/artifacts/rc3-release-channel-publication/publication-manifest.json`
- `.workflow/artifacts/rc3-release-channel-publication/channel-index.json`
- `.workflow/artifacts/rc3-signed-channel-consumer/result.json`
- `.workflow/artifacts/rc3-published-release-support-recovery/result.json`
- `.workflow/artifacts/release/rc3-production-signing-publication-gate.json`

RC4 mirror and fleet evidence must add:

- Hosted transport manifest hash.
- Mirror snapshot hash and freshness window.
- Registry lockfile hash.
- Fleet ring plan hash.
- Rollback baseline hash.
- Revocation and advisory snapshot hash.
- Support bundle redaction proof hash.

## Fail-Closed Requirements

RC4 tasks must fail closed for:

- Hosted manifest hash drift.
- Missing RC3 production verification binding.
- Missing or stale mirror snapshot.
- Unsigned, revoked, or untrusted mirror metadata.
- Registry lockfile mismatch.
- Fleet ring plan drift after approval.
- Rollout without rollback baseline.
- Rollout without exact operator approval.
- Hosted transport attempting active-slot mutation.
- TUI or model replay attempting rollout authority.
- Support bundle containing raw secrets.

## Completion Criteria

RC4-001 is complete when this contract exists and the evidence file records that the next executable task is `RC4-002`, which must define staged rollout authority and rollback boundary before implementation tasks write transport or fleet artifacts.
