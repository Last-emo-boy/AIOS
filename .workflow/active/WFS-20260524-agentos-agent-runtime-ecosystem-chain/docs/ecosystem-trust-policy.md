# Ecosystem Trust Policy

## Purpose

AgentOS ecosystem artifacts extend an OS whose control plane is Agent Runtime. Trust policy therefore decides whether an artifact can be resolved, staged, activated or promoted, but it never grants a shortcut around AgentCore PlanSpec, SecurityExecutionEngine, audit, rollback or replay gates.

Trust is explicit metadata on the artifact and registry snapshot. It is not inferred from a registry URL, local path or operator convenience flag.

## Trust Tiers

### core

`core` artifacts ship with an AgentOS release. They must be covered by the release gate, release provenance, functional replay and ecosystem replay once ecosystem replay exists.

Production defaults:

- signed artifact required
- provenance digest required
- SBOM digest required when executable or policy-bearing content is present
- release gate digest required
- activation may only happen through AgentCore PlanSpec and SecurityExecutionEngine

### verified

`verified` artifacts come from a signed publisher and a verified channel snapshot. They can be production-promotable only when signature, provenance, SBOM requirements, replay gates and policy compatibility pass.

Production defaults:

- signed artifact required
- pinned registry snapshot required
- revocation advisory check required
- deterministic lockfile required

### organization

`organization` artifacts are locally approved overlays, allowlists or private artifacts. They can be production-promotable only inside the organization policy boundary and only when the approval, audit, rollback and replay contract is present.

Production defaults:

- organization trust root required
- local policy owner required
- activation diff must show which core behavior is narrowed or extended
- no organization policy may weaken core invariants

### community

`community` artifacts are discoverable but sandbox-only by default. They are not production-promotable by default and cannot broaden runtime authority.

Production defaults:

- stage allowed only after digest and schema verification
- activation blocked unless a later promotion task adds verified trust, replay and organization approval
- cannot provide privileged adapters, host mutation, secret access or policy weakening

### local-dev

`local-dev` artifacts are explicit developer-mode fixtures. They are useful for iteration and replay authoring but are not production-promotable by default.

Production defaults:

- production activation blocked
- release artifact inclusion blocked
- must be clearly marked in support bundle and provenance output
- cannot be converted to production solely by copying into a trusted path

## Channels

### stable

`stable` is the default production channel. It requires signed snapshots, pinned lockfiles, revocation checks, replay gates and deterministic provenance.

### beta

`beta` may be used for pre-production evaluation. Production activation requires an explicit organization override and the same safety gates as `stable`.

### edge

`edge` is for early integration. It is not production-promotable by default and must not be the baseline for release gates.

### local

`local` is for pinned local snapshots and offline fixtures. Local operation is allowed, but trust tier and promotion eligibility still come from artifact metadata and policy, not from the local path.

## Production Defaults

Unsigned artifacts are blocked in production. Signature missing, digest mismatch, schema mismatch, unknown required fields, revoked status or incompatible runtime versions all fail closed before staging or activation.

Staging is inert. A staged artifact does not change runtime behavior, does not prepare effects and does not mutate host state.

Activation is a runtime operation. `aom activate` must produce an AgentCore PlanSpec, pass through SecurityExecutionEngine, bind exact approval where authority broadens, record audit range, bind rollback handles and update active artifact state only after verification succeeds.

## Blocked Promotions

The following promotions are blocked by default:

- `community` to production
- `local-dev` to production
- unsigned artifact to production
- artifact without provenance to production
- artifact with missing or stale revocation state to production
- artifact that disables no-shell, exact approval, secret-handle, source-to-sink, audit or rollback invariants
- artifact whose optional dependency fallback would mutate the host

Promotion can be introduced later only as an explicit trust workflow with replay, approval, provenance and rollback evidence.

## Revocation Behavior

Registry snapshots carry advisory references. A revoked artifact remains visible for explanation, support and rollback analysis, but future activation is blocked. If a currently active artifact becomes revoked, the active set is marked degraded and the operator projection must show the advisory, affected coordinate and rollback or replacement path.

Revocation checks must work from a pinned local snapshot. Live network access is optional and cannot be a baseline release dependency.
