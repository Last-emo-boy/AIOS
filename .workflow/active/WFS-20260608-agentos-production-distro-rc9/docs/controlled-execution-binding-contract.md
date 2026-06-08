# Controlled Execution Binding Contract

## Scope

RC9-003 defines the contract that must be satisfied before AIOS can move from verified external payload bytes to controlled canary activation or rollback execution. It binds four areas that were blockers after RC8: target enrollment, exact operator approval, AgentCore PlanSpec, and SecurityExecutionEngine approval.

This contract does not enroll real nodes, grant approval, create executable PlanSpecs, execute SecurityExecutionEngine effects, install, activate, rollback, mutate boot metadata, mutate active slots, mutate active artifact sets, mutate production rings, upload support bundles, dispatch remote fleet actions, or grant authority to the mirror, object store, signer, frontend, shell, model replay, or TUI.

## Target Enrollment Boundary

Canary execution requires at least two enrolled targets. A target is eligible only when its enrollment record binds:

- stable `node_id`;
- enrollment state;
- target role;
- current active artifact set digest;
- expected release id;
- expected payload object digest;
- expected descriptor digest;
- compatibility result digest;
- rollback baseline digest;
- support/recovery reference digest;
- audit journal sink;
- health evidence digest;
- node uniqueness proof;
- enrollment freshness window;
- policy version.

The target set artifact must include a deterministic ordered target list, target set digest, observed node count, required minimum node count, duplicate-node check, stale-node check, compatibility summary, rollback readiness summary, and denial reasons.

Projected, missing, duplicate, stale, incompatible, or single-node target sets must produce `target-set-enrollment-denied` and must keep activation, rollback, support upload, recovery execution, production ring mutation, and remote dispatch disabled.

## Exact Approval Boundary

Exact approval is not a human-readable note. It is a hash-bound authorization packet that must bind:

- approval id;
- approving actor;
- actor authority scope;
- release id;
- payload object digest;
- object descriptor digest;
- declared/current reconciliation digest;
- target set digest;
- target node ids;
- requested effect set;
- AgentCore PlanSpec id and hash;
- SecurityExecutionEngine policy id and decision id;
- rollback baseline digest;
- support/recovery digest;
- expiry;
- nonce;
- policy version;
- audit sink.

The approval packet must be denied if it is stale, broad, missing any bound field, scoped to a different release, scoped to a different object digest, scoped to a different target set, grants effects outside the requested effect set, grants mirror/frontend/TUI/shell/model authority, skips AgentCore, skips SecurityExecutionEngine, or omits rollback and recovery bindings.

## AgentCore PlanSpec Boundary

AgentCore must represent controlled activation and rollback as deterministic PlanSpecs. A PlanSpec is executable only when it binds:

- PlanSpec id;
- PlanSpec hash;
- plan kind: `controlled-canary-activation` or `controlled-rollback-drill`;
- release id;
- payload object digest;
- object descriptor digest;
- external object publication digest;
- declared/current reconciliation digest;
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

PlanSpec generation must be deterministic. Any mismatch between the PlanSpec hash and approval packet must deny execution. Any PlanSpec that embeds shell commands, private material, broad target selectors, mutable object references, support upload authority, production ring mutation authority, model authority, TUI authority, or mirror authority must be denied.

## SecurityExecutionEngine Boundary

SecurityExecutionEngine is the only path for side effects. Its approval artifact must bind:

- policy id;
- decision id;
- effect envelope id;
- PlanSpec id and hash;
- exact approval digest;
- target set digest;
- release id;
- payload object digest;
- allowed effect set;
- denied effect set;
- filesystem mutation scope, if any;
- boot metadata mutation scope, if any;
- active slot mutation scope, if any;
- rollback scope;
- support/recovery scope;
- audit sink;
- expiry;
- denial reason when blocked.

If policy evaluation denies or cannot bind every required field, the output must be a denial artifact. A denial artifact is a successful safety outcome when gates are missing.

## Activation Binding

Controlled canary activation may be attempted only when all activation preconditions are true:

- external object descriptor is published and credential-free;
- declared/current drift is reconciled;
- installer quarantine fetch verifies size and digest;
- public signature, revocation, compatibility, rollback baseline, and support/recovery bindings verify;
- target set has at least two enrolled eligible nodes;
- exact approval is granted and unexpired;
- AgentCore activation PlanSpec is bound;
- SecurityExecutionEngine activation approval is bound;
- remote fleet execution is explicitly enabled for the approved target set.

If any precondition is false, the expected artifact is `activation-denied` with exact blockers. It must not mutate boot metadata, active slots, active artifact sets, persistent state, production rings, support upload state, recovery state, or remote dispatch state.

## Rollback Binding

Rollback execution requires a separate rollback approval and rollback PlanSpec. It may proceed only after controlled canary activation evidence exists or after an explicitly approved rollback-only recovery exercise.

Rollback binding must include:

- previous active artifact set digest;
- activated artifact set digest;
- rollback baseline digest;
- rollback target set digest;
- exact rollback approval digest;
- AgentCore rollback PlanSpec id and hash;
- SecurityExecutionEngine rollback decision digest;
- support/recovery digest;
- audit journal sink;
- post-rollback observation requirements.

If any rollback gate is missing, the expected artifact is `rollback-denied` with exact blockers and no side effects.

## TUI And Frontend Boundary

The TUI and mirror frontend may display target enrollment, exact approval, PlanSpec, SecurityExecutionEngine, activation, rollback, and support/recovery state. They may not be authority.

Display surfaces must not:

- create approval;
- broaden approval;
- alter PlanSpec hashes;
- alter SecurityExecutionEngine decisions;
- execute effects;
- mutate active slots;
- mutate production rings;
- upload support bundles;
- dispatch remote fleet actions;
- embed secret material;
- treat model replay output as truth.

## Fail-Closed Rules

Controlled execution binding must fail closed for:

- missing target set;
- fewer than two eligible targets;
- duplicate target ids;
- stale target enrollment;
- incompatible target;
- missing rollback baseline on any target;
- missing support/recovery binding;
- stale, broad, or missing exact approval;
- approval release mismatch;
- approval object digest mismatch;
- approval target set mismatch;
- missing AgentCore PlanSpec;
- PlanSpec hash mismatch;
- PlanSpec embeds broad or authority-bearing actions;
- missing SecurityExecutionEngine decision;
- denied SecurityExecutionEngine decision;
- effect envelope mismatch;
- remote fleet execution disabled;
- missing canary activation evidence before rollback;
- missing rollback approval before rollback;
- TUI, frontend, shell, model, mirror, signer, object storage, or remote registry authority broadening.

## Outputs For Future Tasks

`RC9-020` must enroll or deny the two-node target set. `RC9-021` must bind exact approval to AgentCore PlanSpec and SecurityExecutionEngine approval. `RC9-022` must execute or deny controlled canary activation through these gates. `RC9-030` must execute or deny rollback drill through a separate rollback binding.

Until those tasks pass, RC9 remains `execution-blocked`, `production_ready_claim=false`, `activation_allowed=false`, and `rollback_execution_allowed=false`.
