# RC20 Single-User Distribution Candidate Planning Context

Source: RC19 final closeout audit PASS, non-GA installable image local consumer readiness with reproducible image artifact, installer media, first-user install drill, first boot projection, offline/local channel consumption, post-install update/rollback compatibility, support/recovery evidence, and local consumer smoke.

RC20 objective: move installable image local consumer readiness into a single-user AIOS distribution candidate while preserving AIOS-body-only authority boundaries.

Exploration summary:
- Architecture: the distribution candidate must be contained by canonical release bundle identity, local candidate/stable channel metadata, installer catalog selection, disposable install acceptance, first boot posture, update/rollback drill boundaries, support/recovery references, and durable audit.
- Implementation: follow RC19 task/result/evidence patterns with source hashes, fail-closed matrices, invariant checks, task evidence files, non-GA boundaries, and deterministic local artifacts.
- Integration: RC20 tasks should add scripts and artifacts under RC20 names only, consume RC19 result artifacts, and avoid reusing or staging unrelated pre-existing WIP scripts.
- Risk: single-user distribution evidence must not mutate host rootfs, host active slot, host boot metadata, active artifact set, production rings, support upload, recovery execution, remote dispatch, external mirror/frontend authority, signer authority, shell authority, TUI authority, endpoint authority, or model authority.

Plan overview: 13 tasks in 5 waves, with RC20-001 as the next executable task.
