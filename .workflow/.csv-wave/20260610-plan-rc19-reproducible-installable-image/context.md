# RC19 Reproducible Installable Image Planning Context

Source: RC18 final closeout audit PASS, non-GA isolated installed-system image readiness with disposable image boundary, isolated install/update/rollback, support/recovery evidence, and installed-system consumer smoke.

RC19 objective: move isolated installed-system image readiness into a reproducible installable image artifact and first-user installation path while preserving AIOS-body-only authority boundaries.

Exploration summary:
- Architecture: installable image artifact authority must be contained by deterministic artifact inputs, installer media manifest, boot target descriptor, first-user install target boundary, AgentCore/SecurityExecution gates, rollback/support references, local/offline channel metadata, and durable audit.
- Implementation: follow RC18 task/result/evidence patterns with source hashes, fail-closed matrices, invariant checks, task evidence files, non-GA boundaries, and deterministic local artifacts.
- Integration: RC19 tasks should add scripts and artifacts under RC19 names only, consume RC18 result artifacts, and avoid reusing or staging unrelated pre-existing WIP scripts.
- Risk: installable image evidence must not mutate host rootfs, host active slot, host boot metadata, active artifact set, production rings, support upload, recovery execution, remote dispatch, external mirror/frontend authority, signer authority, shell authority, TUI authority, endpoint authority, or model authority.

Plan overview: 13 tasks in 5 waves, with RC19-001 as the next executable task.
