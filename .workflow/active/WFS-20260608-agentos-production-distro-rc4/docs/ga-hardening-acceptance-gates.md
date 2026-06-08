# GA Hardening Acceptance Gates

## Scope

RC4 is still not a GA production-ready claim. These gates define what RC4 must prove before a later milestone may evaluate GA readiness. RC4 may close hosted transport and fleet rollout proof, but GA requires additional soak, compatibility, support, and security evidence beyond the RC4 contract.

## RC4 Gates

RC4 must prove:

- Hosted release transport metadata is hash-bound to RC3 signed publication evidence.
- Remote registry mirror replay fails closed for tamper, stale, missing, unsigned, revoked, and untrusted metadata.
- Fleet-ring rollout plans bind exact operator approval, rollout policy version, target set, and rollback baseline.
- Signed hosted-channel consumers verify metadata without activation mutation.
- Support/recovery projection explains hosted transport, mirror, fleet ring, and rollback state without raw secrets.
- Promotion gates consume hosted transport and fleet evidence and block on missing or stale inputs.

## Non-GA Boundary

The following remain outside RC4 acceptance:

- Long-duration production soak.
- Full hardware and firmware support matrix.
- Secure boot enrollment rollout.
- Multi-region SLA and disaster recovery validation.
- Upgrade compatibility matrix across supported versions.
- External security audit signoff.
- Customer production support process validation.

RC4 artifacts must keep `production_ready_claim=false`.

## Required Verification Classes

RC4 implementation tasks should produce:

- Positive hosted transport replay.
- Positive mirror replay.
- Positive signed hosted-channel consumer smoke.
- Positive fleet-ring rollout projection.
- Positive rollback drill projection.
- Positive support/recovery projection.
- Negative hosted transport fixtures.
- Negative mirror fixtures.
- Negative fleet rollout authority fixtures.
- Negative support redaction fixtures.
- Promotion gate integration proof.

## Completion Rule

RC4 final audit may pass only when all RC4 gates are present, current, hash-bound, and fail-closed. Passing RC4 does not imply GA.
