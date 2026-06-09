# RC17 Exact Install/Update Execute-Or-Deny Planning Context

Source: RC16 final closeout audit PASS, non-GA distributable packaging readiness with install/update denied.

RC17 objective: bind exact install/update execution gates and run controlled local install/update execute-or-deny evidence while preserving AIOS-body-only authority boundaries.

Exploration summary:
- Architecture: install/update authority must remain inside local release evidence, exact target identity, exact approval, AgentCore, SecurityExecution, rollback/support evidence, and durable audit.
- Implementation: follow RC16 task/result/evidence patterns with source hashes, fail-closed matrices, invariant checks, task evidence files, and non-GA boundaries.
- Integration: RC17 execution tasks should add scripts and artifacts under RC17 names only, and should consume RC16 result artifacts instead of reinterpreting mirror, frontend, signer, shell, TUI, or model output.
- Risk: install/update effects must not be fabricated from projections, and any controlled local effect must not mutate host active slot, host boot metadata, production rings, support upload, recovery execution, or remote dispatch.

Plan overview: 12 tasks in 5 waves, with RC17-001 as the next executable task.
