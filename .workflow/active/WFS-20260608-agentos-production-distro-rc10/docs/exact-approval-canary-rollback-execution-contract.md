# Exact Approval Canary Activation And Rollback Execution Contract

## Scope

RC10-003 defines the execution enablement boundary for AIOS controlled canary activation and controlled rollback drill after real external object publication, drift-zero reconciliation, and installer quarantine fetch verification.

This contract upgrades the RC9 controlled execution binding from denial-only rules to an enablement-ready contract. It defines what must be true before an activation or rollback effect may run through AgentCore and SecurityExecutionEngine.

This contract does not enroll real nodes, grant approval, create executable PlanSpecs, execute effects, install, activate, rollback, mutate boot metadata, mutate active slots, mutate active artifact sets, mutate production rings, upload support bundles, dispatch remote fleet actions, or grant authority to the mirror, object store, signer, frontend, shell, model replay, or TUI.

## Pre-Execution Chain

Controlled activation may be considered only when all prior RC10 evidence exists and is current:

- external object descriptor is `published-drift-zero`;
- declared/current artifact drift count is `0`;
- descriptor canonical hash matches the mirror, installer handoff, and support/recovery reference;
- installer quarantine fetch verified byte length and SHA-256;
- public signature target and receipt are valid;
- revocation snapshot is current and not revoked;
- installer compatibility evidence is current;
- rollback baseline is current;
- support/recovery references are current;
- target set has at least two eligible canary nodes;
- exact approval is unexpired and hash-bound;
- AgentCore PlanSpec hash matches the approval packet;
- SecurityExecutionEngine effect envelope matches the PlanSpec and approval packet;
- remote execution is enabled only for the approved target set.

Any missing or stale item produces denial evidence. A denial artifact is successful safety behavior when gates are incomplete.

## Canary Target Enrollment

At least two canary target nodes are required. A target is eligible only if its enrollment record binds:

- stable `node_id`;
- target role: `canary`;
- enrollment state: `enrolled`;
- current active artifact set digest;
- desired artifact set digest;
- expected release id;
- expected external object digest;
- expected descriptor digest;
- compatibility result digest;
- rollback baseline digest;
- support/recovery reference digest;
- audit journal sink;
- health evidence digest;
- node uniqueness proof;
- enrollment freshness window;
- policy version.

The target set artifact must include:

- deterministic ordered target list;
- target set digest;
- observed target count;
- required minimum target count;
- duplicate-node check;
- stale-node check;
- compatibility summary;
- rollback readiness summary;
- support/recovery summary;
- audit sink summary;
- denial reasons when blocked.

Projected, missing, duplicate, stale, incompatible, or single-node target sets must deny activation and rollback execution.

## Exact Approval Packet

Exact approval must be a hash-bound packet, not a note or UI action. It must bind:

- approval id;
- approving actor;
- actor authority scope;
- approval kind: `controlled-canary-activation` or `controlled-rollback-drill`;
- release id;
- external object digest;
- object descriptor digest;
- drift-zero reconciliation digest;
- installer quarantine fetch digest;
- target set digest;
- target node ids;
- requested effect set;
- AgentCore PlanSpec id;
- AgentCore PlanSpec hash;
- SecurityExecutionEngine policy id;
- SecurityExecutionEngine decision id;
- effect envelope id;
- rollback baseline digest;
- support/recovery digest;
- audit sink;
- expiry;
- nonce;
- policy version.

Approval must be denied if it is stale, broad, missing any bound field, scoped to a different release, scoped to a different object digest, scoped to a different target set, grants effects outside the requested effect set, skips AgentCore, skips SecurityExecutionEngine, omits rollback/recovery bindings, or grants authority to mirror, frontend, TUI, shell, model replay, object storage, signer reachability, support endpoint, or remote registry.

## AgentCore PlanSpec

AgentCore must represent activation and rollback as deterministic PlanSpecs.

An activation PlanSpec must bind:

- PlanSpec id;
- PlanSpec hash;
- plan kind: `controlled-canary-activation`;
- release id;
- external object digest;
- object descriptor digest;
- drift-zero reconciliation digest;
- installer quarantine fetch digest;
- target set digest;
- exact approval digest;
- SecurityExecutionEngine policy decision digest;
- rollback baseline digest;
- support/recovery digest;
- expected observations;
- rollback path;
- audit journal path;
- expiry;
- policy version.

A rollback PlanSpec must bind:

- PlanSpec id;
- PlanSpec hash;
- plan kind: `controlled-rollback-drill`;
- release id;
- previous active artifact set digest;
- activated artifact set digest;
- rollback baseline digest;
- rollback target set digest;
- exact rollback approval digest;
- SecurityExecutionEngine rollback decision digest;
- support/recovery digest;
- expected post-rollback observations;
- audit journal path;
- expiry;
- policy version.

PlanSpec generation must be deterministic. Any mismatch between the PlanSpec hash and approval packet must deny execution. Any PlanSpec that embeds shell commands, private material, broad target selectors, mutable object references, support upload authority, production ring mutation authority, model authority, frontend authority, TUI authority, mirror authority, signer authority, or object storage authority must be denied.

## SecurityExecutionEngine Effect Envelope

SecurityExecutionEngine is the only side-effect path.

An activation effect envelope must bind:

- policy id;
- decision id;
- effect envelope id;
- effect kind: `controlled-canary-activation`;
- PlanSpec id and hash;
- exact approval digest;
- target set digest;
- release id;
- external object digest;
- allowed effect set;
- denied effect set;
- filesystem mutation scope;
- boot metadata mutation scope;
- active artifact mutation scope;
- active slot mutation scope;
- rollback scope;
- support/recovery scope;
- audit sink;
- expiry;
- denial reason when blocked.

A rollback effect envelope must bind:

- policy id;
- decision id;
- effect envelope id;
- effect kind: `controlled-rollback-drill`;
- rollback PlanSpec id and hash;
- exact rollback approval digest;
- rollback target set digest;
- previous artifact set digest;
- activated artifact set digest;
- rollback baseline digest;
- allowed rollback effect set;
- denied effect set;
- mutation scope;
- support/recovery scope;
- audit sink;
- expiry;
- denial reason when blocked.

If policy evaluation denies or cannot bind every required field, the output must be a denial artifact and no side effect may occur.

## Controlled Activation Outcomes

Allowed activation outcomes:

- `activation-executed-canary`: all gates passed and SecurityExecutionEngine executed only the approved canary effect set;
- `activation-denied-gate-missing`: at least one required gate is missing;
- `activation-denied-approval-invalid`: exact approval is missing, stale, broad, or mismatched;
- `activation-denied-planspec-mismatch`: AgentCore PlanSpec is missing or mismatched;
- `activation-denied-security-execution`: SecurityExecutionEngine denied or could not bind the effect envelope;
- `activation-denied-authority-broadening`: any unauthorized authority is detected.

Even `activation-executed-canary` must not mutate production rings. It may only mutate approved canary target state within the effect envelope scope and must emit audit evidence for before/after artifact sets, observations, and recovery path.

## Controlled Rollback Outcomes

Rollback requires separate rollback approval and rollback PlanSpec. It may execute only after controlled canary activation evidence exists or after an explicitly approved rollback-only recovery exercise.

Allowed rollback outcomes:

- `rollback-executed-canary`: all rollback gates passed and SecurityExecutionEngine executed only the approved rollback effect set;
- `rollback-denied-no-activation-evidence`: activation evidence is absent and no rollback-only recovery exercise was approved;
- `rollback-denied-approval-invalid`: rollback approval is missing, stale, broad, or mismatched;
- `rollback-denied-planspec-mismatch`: rollback PlanSpec is missing or mismatched;
- `rollback-denied-security-execution`: SecurityExecutionEngine denied or could not bind the rollback envelope;
- `rollback-denied-authority-broadening`: any unauthorized authority is detected.

Rollback evidence must bind previous artifact set, activated artifact set, rollback baseline, target nodes, approval digest, PlanSpec hash, effect envelope, support/recovery references, audit journal, and post-rollback observations.

## TUI Frontend And Support Boundary

TUI and frontend surfaces may display target enrollment, approval, PlanSpec, SecurityExecutionEngine, activation, rollback, and support/recovery state. They are projection surfaces only.

They must not:

- create approval;
- broaden approval;
- alter PlanSpec hashes;
- alter SecurityExecutionEngine decisions;
- execute effects;
- mutate active slots;
- mutate active artifact sets;
- mutate production rings;
- upload support bundles;
- dispatch remote fleet actions;
- embed secret material;
- treat model replay output as truth.

Support/recovery evidence may be generated locally and redacted. Support upload remains separately gated and disabled unless a later task explicitly proves its policy.

## Fail-Closed Rules

Controlled execution enablement must fail closed for:

- missing published drift-zero descriptor;
- nonzero declared/current drift count;
- missing installer quarantine fetch evidence;
- invalid public signature evidence;
- stale or revoked revocation snapshot;
- missing installer compatibility;
- missing rollback baseline;
- missing support/recovery binding;
- missing target set;
- fewer than two eligible targets;
- duplicate target ids;
- stale target enrollment;
- incompatible target;
- stale, broad, or missing exact approval;
- approval release mismatch;
- approval object digest mismatch;
- approval target set mismatch;
- missing AgentCore PlanSpec;
- PlanSpec hash mismatch;
- PlanSpec authority broadening;
- missing SecurityExecutionEngine decision;
- denied SecurityExecutionEngine decision;
- effect envelope mismatch;
- remote execution disabled for the approved target set;
- missing canary activation evidence before rollback;
- missing rollback approval;
- rollback PlanSpec mismatch;
- rollback effect envelope mismatch;
- TUI, frontend, shell, model, mirror, signer, object storage, support endpoint, or remote registry authority broadening.

## Outputs For Future Tasks

`RC10-020` must enroll or deny the two-node target set. `RC10-021` must bind exact approval to AgentCore PlanSpec and SecurityExecutionEngine effect envelope. `RC10-022` must execute or deny controlled canary activation through these gates. `RC10-030` must execute or deny rollback drill through a separate rollback binding.

Until those tasks pass, RC10 remains `execution-blocked`, `production_ready_claim=false`, `activation_allowed=false`, and `rollback_execution_allowed=false`.
