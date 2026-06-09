# RC18 Isolated Installed-System Drill Planning Context

Source: RC17 final closeout audit PASS, non-GA exact install/update execute-or-deny readiness with repo-local install, update, rollback, support, and consumer evidence.

RC18 objective: move exact install/update/rollback evidence from repo-local artifacts into a disposable installed-system image or VM boundary while preserving AIOS-body-only authority boundaries.

Exploration summary:
- Architecture: installed-system drill authority must be contained by a disposable image state root, explicit write surface, AgentCore PlanSpec, SecurityExecution allow, rollback baseline, support/recovery references, and durable audit.
- Implementation: follow RC17 task/result/evidence patterns with source hashes, fail-closed matrices, invariant checks, task evidence files, non-GA boundaries, and deterministic local artifacts.
- Integration: RC18 tasks should add scripts and artifacts under RC18 names only, consume RC17 result artifacts, and avoid reusing or staging unrelated pre-existing WIP scripts.
- Risk: isolated image evidence must not mutate host rootfs, host active slot, host boot metadata, active artifact set, production rings, support upload, recovery execution, remote dispatch, mirror/frontend authority, signer authority, shell authority, TUI authority, or model authority.

Plan overview: 12 tasks in 5 waves, with RC18-001 as the next executable task.
