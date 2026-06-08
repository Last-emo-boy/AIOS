# AIOS TASK

Source: `research.md`
Workflow: `.workflow/active/WFS-20260609-agentos-production-distro-rc13`
Previous workflow: `.workflow/active/WFS-20260609-agentos-production-distro-rc12`
Maestro session: `.workflow/.maestro/maestro-20260607-141323`

## 目标

构建 Linux-based AgentOS：先完成可启动 MVP，再补齐底层 Agent Core Runtime 和安全执行底座，最终推进到可发行的 AgentOS distribution。

一句话边界：

> Kernel handles reality；`agentd` handles intention。

## 当前判断

- 不重写内核；MVP 主线选择 Linux。
- 不把 LLM 放进 kernel；模型只能通过 `Model Broker` 参与计划、分类、摘要或解释。
- 不默认暴露任意 shell；所有副作用必须走 semantic tool、policy、capability、audit、rollback。
- Firecracker 作为危险动作隔离层进入 Alpha，不阻塞 MVP。
- seL4/Genode 是高安全版独立产品线，不拖慢 Linux 主线。

## 当前进度

- 当前任务：Production Distro RC14 `RC14-000` planning 已完成，当前 maestro 指针进入 `RC14-001` local execution readiness contract。RC14 只推进 AIOS 本体本地信任 / 受控执行 readiness，不做 mirror 前端、Nginx/TLS、远端 signer、object storage provisioning、remote dispatch infrastructure、private signing material handling 或 production ring mutation；RC14 仍保持 non-GA，不代表 GA production-ready。
- 当前正式里程碑已经关闭到 Production Distro RC8：RC6 已完成 installable signed payload channel metadata、bootstrap/installer consumption、storage/TLS policy、canary packet 和 rollback precondition projection；RC7 已完成 signed payload consumption、revocation、compatibility、rollback baseline、HTTPS mirror hardening、gated canary activation 和 gated rollback drill evidence；RC8 Wave 0 已完成 `RC8-001` real installable payload and controlled execution smoke contract、`RC8-002` immutable payload object descriptor and byte boundary、`RC8-003` public signature artifact ingestion and receipt boundary，Wave 1 已完成 `RC8-010` real installable payload object descriptor projection、`RC8-011` public signature artifact ingestion 和 `RC8-012` signed object descriptor fail-closed fixtures，Wave 2 已完成 `RC8-020` installer VM preflight and quarantined object-fetch smoke、`RC8-021` installer byte/signature/storage/compatibility fail-closed fixtures 和 `RC8-022` mirror metadata/frontend consistency refresh，Wave 3 已完成 `RC8-030` exact-approved canary activation smoke packet、`RC8-031` controlled rollback drill fail-closed evidence 和 `RC8-032` support/recovery evidence binding，closeout `RC8-040` 已完成。RC9 Wave 0 已完成 `RC9-001` external object storage and controlled canary execution contract、`RC9-002` external object descriptor publication and artifact drift reconciliation contract 和 `RC9-003` controlled execution binding contract，Wave 1 已完成 `RC9-010` external object publication candidate denial evidence、`RC9-011` artifact drift reconciliation denial evidence 和 `RC9-012` external object installer fetch fail-closed evidence，Wave 2 已完成 `RC9-020` two-node canary enrollment denial evidence、`RC9-021` exact approval execution binding denial evidence 和 `RC9-022` controlled canary activation denial evidence，Wave 3 已完成 `RC9-030` controlled rollback drill denial evidence 和 `RC9-031` controlled execution support/recovery binding evidence，closeout `RC9-040` 已完成。下一步进入 Production Distro RC10 planning。`.workflow/active/WFS-20260525-agentos-console-beta-production-ux` 的结论仍是 `console-beta`，RC0/RC1/RC2/RC3/RC4/RC5/RC6/RC7/RC8/RC9 当前都不是 GA production-ready claim。
- Production Distro RC0 final audit 明确列出 `RC0-001` 到 `RC0-010` 共 10 个 task；当前 10 个 RC0 task 和 `RC0-FINAL-001` 已全部完成，RC1 Wave 0 到 Wave 3 已全部完成，RC2 Wave 0 到 Wave 3 已全部完成，RC3 Wave 0 到 Wave 3 已完成并写入 final audit；RC4 已完成，Wave 0（`RC4-001` 到 `RC4-004`）、Wave 1（`RC4-010` 到 `RC4-013`）、Wave 2（`RC4-020` 到 `RC4-023`）和 `RC4-030` final audit 均已完成；RC5 已完成，`RC5-001`、`RC5-002`、`RC5-003`、`RC5-010`、`RC5-011`、`RC5-012`、`RC5-013`、`RC5-020`、`RC5-021`、`RC5-022` 和 `RC5-030` 已完成。RC6 已完成，`RC6-001`、`RC6-002`、`RC6-003`、`RC6-004`、`RC6-010`、`RC6-011`、`RC6-012`、`RC6-020`、`RC6-021`、`RC6-022`、`RC6-030`、`RC6-031` 和 `RC6-040` 已完成；RC7 Wave 0 已完成 `RC7-001`、`RC7-002` 和 `RC7-003`，RC7 Wave 1 已完成 `RC7-010`、`RC7-011` 和 `RC7-012`，RC7 Wave 2 已完成 `RC7-020`、`RC7-021` 和 `RC7-022`，RC7 Wave 3 已完成 `RC7-030`、`RC7-031` 和 `RC7-032`，RC7 closeout `RC7-040` 已完成。RC8 Wave 0 到 Wave 3 以及 closeout `RC8-040` 已完成，RC9 已启动，Wave 0 的 `RC9-001`、`RC9-002` 和 `RC9-003` 已完成，Wave 1 的 `RC9-010`、`RC9-011` 和 `RC9-012` 已完成，Wave 2 的 `RC9-020`、`RC9-021` 和 `RC9-022` 已完成，Wave 3 的 `RC9-030` 和 `RC9-031` 已完成，closeout `RC9-040` 已完成。RC10 Wave 0 到 Wave 3 以及 closeout `RC10-040` 已完成。RC11 planning、trust handoff contract、release object byte map、declared/current drift-zero reconciliation、external descriptor verification、installer quarantine verifier、installer AgentCore/SecurityExecution handoff、two-target canary approval package、controlled canary activation、controlled rollback support/recovery 和 `RC11-050` final closeout audit 已完成。RC12 planning `RC12-000`、contract `RC12-001`、publication binding `RC12-010`、drift-zero reconciliation `RC12-011`、object trust verification `RC12-012`、quarantine fetch verification `RC12-020`、AgentCore/SecurityExecution package binding `RC12-021`、canary target approval binding `RC12-030`、controlled canary activation `RC12-040`、controlled rollback drill `RC12-041` 和 `RC12-050` final closeout audit 已完成。RC13 planning `RC13-000`、local trust unblock contract `RC13-001`、declared/current drift-zero repair `RC13-010`、object manifest descriptor binding `RC13-011`、freshness/revocation authority `RC13-012`、quarantine preflight `RC13-020`、AgentCore executable PlanSpec readiness `RC13-021`、SecurityExecution allow preconditions `RC13-022`、two-target identity enrollment `RC13-030`、exact approval audit binding `RC13-031`、controlled activation `RC13-040`、controlled rollback support/recovery `RC13-041` 和 `RC13-050` final closeout audit 已完成；下一步进入 `RC14-planning`。

- `RC11-010` 已完成：新增 `scripts/project-rc11-release-object-byte-map.ps1`，生成 `.workflow/artifacts/rc11-release-object-byte-map/release-object-byte-map.json`、`immutable-descriptor-candidate.json`、`descriptor-candidate-report.json`、`result.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/RC11-010-release-object-byte-map.json`。结果为 `passed`、9 checks、0 failed checks；descriptor candidate 保持 `production_ready_claim=false`、`install_allowed=false`、`activation_allowed=false`、`rollback_execution_allowed=false`，且未执行 payload upload、remote fetch、quarantine write、install、activation、rollback、support upload、remote dispatch、production ring mutation、signer infra、Nginx 或 mirror frontend 变更。
- `RC11-011` 已完成：新增 `scripts/project-rc11-declared-current-drift-zero.ps1`，生成 `.workflow/artifacts/rc11-declared-current-drift-zero/declared-current-drift-zero-reconciliation.json`、`drift-zero-denial.json`、`external-descriptor-verification-handoff.json`、`result.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/RC11-011-declared-current-drift-zero.json`。结果为 `passed`、7 checks、0 failed checks；共 40 项 explicit hash-bound comparisons，`rc11_self_drift=0`，`carried_forward_drift=13`，因此 drift-zero 仍被 deny，object trust、external descriptor verification、installer quarantine fetch、install、activation、rollback、support upload、remote dispatch、production ring mutation、signer infra、Nginx 和 mirror frontend authority 全部保持 false。
- `RC11-012` 已完成：新增 `scripts/project-rc11-external-object-descriptor-verification.ps1`，生成 `.workflow/artifacts/rc11-external-object-descriptor-verification/descriptor-verification-report.json`、`descriptor-verification-denial.json`、`descriptor-fail-closed-matrix.json`、`result.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/RC11-012-external-object-descriptor-verification.json`。结果为 `passed`、8 checks、0 failed checks；descriptor 与当前 payload bytes 匹配，但 external URI 未发布且 drift-zero 未通过，所以 verification 被 deny，12 个 fail-closed cases 全部 deny，未做 network probe、未信任 endpoint reachability，install / activation / rollback / support upload / remote dispatch / production ring mutation 全部为 false。
- `RC11-020` 已完成：新增 `scripts/project-rc11-installer-quarantine-verifier.ps1`，生成 `.workflow/artifacts/rc11-installer-quarantine-verifier/result.json`、`quarantine-fetch-report.json`、`installer-fail-closed-matrix.json`、`installer-gate-report.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/RC11-020-installer-quarantine-verifier.json`。结果为 `passed`、7 checks、0 failed checks；quarantine fetch 在 network 前按预期 deny，20 个 fail-closed cases 全部通过，未下载 payload、未写 quarantine、未解释 payload、未 install / activation / rollback / support upload / remote dispatch / production ring mutation。
- `RC11-021` 已完成：新增 `scripts/project-rc11-installer-agentcore-security-handoff.ps1`，生成 `.workflow/artifacts/rc11-installer-agentcore-security-handoff/result.json`、`agentcore-planspec-handoff.json`、`security-execution-effect-envelope.json`、`handoff-denial.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/RC11-021-installer-agentcore-security-handoff.json`。结果为 `passed`、8 checks、0 failed checks；installer preflight evidence 已 hash-bound 到 AgentCore PlanSpec candidate，SecurityExecution effect envelope 继续 deny-by-default，12 个 handoff fail-closed cases 全部通过，未 install / activation / rollback / support upload / remote dispatch / production ring mutation。
- `RC11-030` 已完成：新增 `scripts/project-rc11-two-target-canary-approval.ps1`，生成 `.workflow/artifacts/rc11-two-target-canary-approval/result.json`、`canary-target-set.json`、`exact-approval-package.json`、`approval-fail-closed-matrix.json`、`controlled-activation-approval-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/RC11-030-two-target-canary-approval.json`。结果为 `passed`、9 checks、0 failed checks；target set 记录 2 个 required target slots 但因 observed candidate 仍为 1、enrolled target 为 0 而 deny，exact approval package 记录 actor / release / object / target-set / AgentCore / SecurityExecution / rollback / support binding 字段并 deny 缺失 target ids、audit sink、expiry 和 nonce，15 个 approval fail-closed cases 全部通过，未 activation / rollback / remote dispatch。
- `RC11-031` 已完成：新增 `scripts/project-rc11-controlled-canary-activation.ps1`，生成 `.workflow/artifacts/rc11-controlled-canary-activation/result.json`、`activation-gate-report.json`、`activation-denial-evidence.json`、`controlled-activation-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/RC11-031-controlled-canary-activation.json`。结果为 `passed`、9 checks、0 failed checks、10 个 denial cases 全部通过；activation 按预期 deny，原因包括 object trust、quarantine/preflight、two-target enrollment、exact approval、executable AgentCore PlanSpec、SecurityExecution approval、audit binding 和 remote fleet gates 仍缺失；未执行 install / activation / rollback / support upload / recovery / remote dispatch / production ring mutation。
- `RC11-040` 已完成：新增 `scripts/project-rc11-controlled-rollback-support-recovery.ps1`，生成 `.workflow/artifacts/rc11-controlled-rollback-support-recovery/result.json`、`rollback-planspec-requirement.json`、`rollback-support-gate-report.json`、`rollback-support-denial-evidence.json`、`support-recovery-evidence-chain.json`、`controlled-execution-support-bundle.json`、`recovery-reference-index.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/RC11-040-controlled-rollback-support-recovery.json`。结果为 `passed`、10 checks、0 failed checks、11 个 denial cases 全部通过；rollback/support/recovery 按预期 deny，原因包括 controlled activation 未执行、target ids、separate rollback approval、AgentCore rollback PlanSpec、SecurityExecution rollback approval、audit journal、post-rollback observations 和 remote fleet gates 仍缺失；support bundle 保持 redacted/local-only，未执行 rollback / support upload / recovery / remote dispatch / production ring mutation。
- `RC11-050` 已完成：新增 `scripts/run-rc11-final-closeout-audit.ps1`，生成 `.workflow/artifacts/rc11-final-closeout-audit/result.json`、`.workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/FINAL-AUDIT-20260609-production-distro-rc11.json`、`.workflow/active/WFS-20260609-agentos-production-distro-rc11/docs/final-rc11-closeout-summary.md` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/RC11-050-final-closeout-audit.json`。审计结论为 `PASS`、16 checks、0 blockers；RC11 作为 non-GA fail-closed milestone 关闭，仍保持 external object trust、drift-zero、quarantine fetch、exact approval、AgentCore executable PlanSpec、SecurityExecution allow、activation、rollback、support upload、recovery、remote dispatch、mirror/frontend/nginx/signer authority 和 production ring mutation 全部 disabled；下一步进入 Production Distro RC12 planning。
- `RC12-000` 已完成：新增 `.workflow/active/WFS-20260609-agentos-production-distro-rc12/plan.json`、`workflow-session.json`、`.task/TASK-RC12-*.json`、`docs/rc12-real-object-controlled-unblock-plan.md`、`evidence/RC12-000-planning.json` 和 `.workflow/.csv-wave/20260609-plan-rc12-real-object-controlled-unblock/` 规划会话。RC12 从 RC11 final audit blockers 出发，规划 real object publication binding、drift-zero、object trust verification、quarantine fetch、AgentCore/SecurityExecution executable package、canary exact approval、controlled activation、separate rollback drill 和 final audit；仍保持 `production_ready_claim=false`，不做 mirror frontend / Nginx/TLS / remote signer / object storage provisioning / remote dispatch infrastructure / production ring mutation。当前 next task 是 `RC12-001`。
- `RC12-001` 已完成：新增 `.workflow/active/WFS-20260609-agentos-production-distro-rc12/docs/rc12-real-object-controlled-unblock-contract.md` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-001-real-object-controlled-unblock-contract.json`。合同冻结 external object transport 到 local AIOS trust 的 gate order：URI classification、byte/descriptor binding、drift-zero、freshness/revocation、quarantine fetch、pre-interpretation verification、AgentCore executable PlanSpec、SecurityExecution allow、two-target canary、exact approval、controlled activation 和 separate rollback approval；仍保持 `production_ready_claim=false`，不做 mirror/frontend/nginx/signer/object-storage/remote-dispatch/prod-ring 变更。当前 next task 是 `RC12-010`。
- `RC12-010` 已完成：新增 `scripts/project-rc12-external-object-publication-binding.ps1`，生成 `.workflow/artifacts/rc12-external-object-publication-binding/result.json`、`publication-binding.json`、`publication-denial.json`、`publication-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-010-external-object-publication-binding.json`。结果为 `passed`、10 checks、0 failed checks；current payload bytes、descriptor、manifest、checksum set、signature target、revocation、freshness、compatibility、rollback 和 support references 已 hash-bound，publication 按预期 deny，blockers 是 `external-https-object-uri-not-published`、`freshness-window-missing` 和 `declared-current-drift-zero-not-proved`；未执行 payload upload、object storage provisioning、network probe、install、activation、rollback、support upload、remote dispatch、mirror/frontend/nginx/signer 变更或 production ring mutation。当前 next task 是 `RC12-011`。
- `RC12-011` 已完成：新增 `scripts/project-rc12-declared-current-drift-zero.ps1`，生成 `.workflow/artifacts/rc12-declared-current-drift-zero/result.json`、`declared-current-drift-zero-reconciliation.json`、`drift-zero-denial.json`、`object-trust-verification-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-011-declared-current-drift-zero.json`。结果为 `passed`、8 checks、0 failed checks；共 60 项 explicit hash-bound comparisons，`rc12_self_drift=4`、`carried_forward_drift=13`、`drift_zero=false`，因此 object trust、quarantine fetch、install、activation、rollback、support upload、recovery、remote dispatch 和 production mutation 全部保持 denied。当前 next task 是 `RC12-012`。
- `RC12-012` 已完成：新增 `scripts/project-rc12-object-trust-verification.ps1`，生成 `.workflow/artifacts/rc12-object-trust-verification/result.json`、`object-trust-report.json`、`object-trust-denial.json`、`object-trust-fail-closed-matrix.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-012-object-trust-verification.json`。结果为 `passed`、10 checks、0 failed checks、15 个 fail-closed cases 全部 denied；object trust 仍按预期 deny，endpoint reachability 被记录为非 authority，未执行 network probe、payload fetch、quarantine write、payload interpretation、install、activation、rollback、support upload、recovery、remote dispatch 或 production mutation。当前 next task 是 `RC12-020`。
- `RC12-020` 已完成：新增 `scripts/project-rc12-quarantine-fetch-verification.ps1`，生成 `.workflow/artifacts/rc12-quarantine-fetch-verification/result.json`、`quarantine-fetch-report.json`、`quarantine-fetch-fail-closed-matrix.json`、`quarantine-fetch-gate-report.json`、`agentcore-security-package-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-020-quarantine-fetch-verification.json`。结果为 `passed`、10 checks、0 failed checks、27 个 fail-closed cases 全部通过；quarantine fetch 因 object trust 仍为 false 在 network 前 deny，未执行 network fetch、remote payload download、quarantine write、payload interpretation、install、activation、rollback、support upload、recovery、remote dispatch 或 production mutation。当前 next task 是 `RC12-021`。
- `RC12-021` 已完成：新增 `scripts/project-rc12-agentcore-security-execution-package.ps1`，生成 `.workflow/artifacts/rc12-agentcore-security-execution-package/result.json`、`agentcore-planspec-package.json`、`security-execution-effect-envelope.json`、`execution-package-denial.json`、`execution-package-fail-closed-matrix.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-021-agentcore-security-execution-package.json`。结果为 `passed`、9 checks、0 failed checks、17 个 fail-closed cases 全部通过；RC12-020 quarantine evidence 已 hash-bound 到 AgentCore PlanSpec package candidate，但 installer preflight 未 verified，因此 PlanSpec 仍 non-executable，SecurityExecution 按预期 deny，未执行 install、activation、rollback、support upload、recovery、remote dispatch 或 production mutation。当前 next task 是 `RC12-030`。
- `RC12-030` 已完成：新增 `scripts/project-rc12-canary-target-approval-binding.ps1`，生成 `.workflow/artifacts/rc12-canary-target-approval-binding/result.json`、`canary-target-set.json`、`exact-approval-package.json`、`approval-fail-closed-matrix.json`、`controlled-activation-approval-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-030-canary-target-approval-binding.json`。结果为 `passed`、10 checks、0 failed checks、23 个 fail-closed cases 全部通过；至少 2 个 canary target identities 被记录为 activation authority 前置条件但仍未 enrolled，exact approval 绑定 actor / release / object digest / target set / AgentCore PlanSpec / SecurityExecution envelope / rollback / support-recovery 字段并因缺失 target identities、approval actor、audit sink、nonce 和 expiry 被 deny，未执行 activation、rollback、support upload、recovery、remote dispatch 或 production mutation。当前 next task 是 `RC12-040`。
- `RC12-040` 已完成：新增 `scripts/project-rc12-controlled-canary-activation.ps1`，生成 `.workflow/artifacts/rc12-controlled-canary-activation/result.json`、`activation-gate-report.json`、`activation-denial-evidence.json`、`controlled-activation-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-040-controlled-canary-activation.json`。结果为 `passed`、9 checks、0 failed checks、11 个 activation denial cases 全部通过；activation 因 object trust、quarantine verification、installer preflight、two-target enrollment、exact approval、audit sink、nonce、expiry、executable AgentCore PlanSpec 和 SecurityExecution allow 仍缺失而 deny，未伪造 activation audit，未执行 install、activation、rollback、support upload、recovery、remote dispatch 或 production mutation。当前 next task 是 `RC12-041`。
- `RC12-041` 已完成：新增 `scripts/project-rc12-controlled-rollback-drill.ps1`，生成 `.workflow/artifacts/rc12-controlled-rollback-drill/result.json`、`rollback-planspec-requirement.json`、`rollback-drill-gate-report.json`、`rollback-drill-denial-evidence.json`、`support-recovery-evidence-chain.json`、`controlled-execution-support-bundle.json`、`recovery-reference-index.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-041-controlled-rollback-drill.json`。结果为 `passed`、10 checks、0 failed checks、13 个 rollback denial cases 全部通过；rollback/support/recovery 因 controlled activation 未执行、rollback target identities、separate rollback approval、AgentCore rollback PlanSpec、SecurityExecution rollback allow、audit journal、post-rollback observations 和 remote fleet gates 仍缺失而 deny；support bundle 保持 redacted/local-only，未执行 rollback、support upload、recovery、remote dispatch、install、activation 或 production mutation。当前 next task 是 `RC12-050`。
- `RC12-050` 已完成：新增 `scripts/run-rc12-final-closeout-audit.ps1`，生成 `.workflow/artifacts/rc12-final-closeout-audit/result.json`、`.workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/FINAL-AUDIT-20260609-production-distro-rc12.json`、`.workflow/active/WFS-20260609-agentos-production-distro-rc12/docs/final-rc12-closeout-summary.md` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-050-final-closeout-audit.json`。审计结论为 `PASS`、14 checks、0 blockers；RC12 作为 non-GA fail-closed milestone 关闭，仍保持 object publication、drift-zero、object trust、quarantine fetch、AgentCore executable PlanSpec、SecurityExecution allow、two-target enrollment、exact approval、activation、rollback、support upload、recovery、remote dispatch、mirror/frontend/nginx/signer authority 和 production mutation disabled；下一步进入 Production Distro RC13 planning。
- `RC13-000` 已完成：新增 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/plan.json`、`workflow-session.json`、`.task/TASK-RC13-*.json`、`docs/rc13-local-trust-unblock-plan.md`、`evidence/RC13-000-planning.json` 和 `.workflow/.csv-wave/20260609-plan-rc13-local-trust-unblock/context.md` 规划会话。RC13 从 RC12 final audit blockers 出发，规划 declared/current drift-zero repair、object manifest/descriptor binding、freshness/revocation authority、quarantine preflight、AgentCore executable PlanSpec readiness、SecurityExecution allow preconditions、two-target identity enrollment、exact approval audit binding、controlled activation、separate rollback support/recovery 和 final audit；仍保持 `production_ready_claim=false`，不做 mirror frontend / Nginx/TLS / remote signer / object storage provisioning / remote dispatch infrastructure / private signing material handling / production ring mutation。当前 next task 是 `RC13-001`。
- `RC13-001` 已完成：新增 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/rc13-local-trust-unblock-contract.md` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-001-local-trust-unblock-contract.json`。合同冻结 gate order：declared/current drift-zero、object manifest/descriptor consistency、freshness/revocation/public signature authority、object trust、quarantine preflight、AgentCore executable PlanSpec、SecurityExecution allow、two-target local canary identity、exact approval audit sink nonce expiry、controlled activation 和 separate rollback approval；仍保持 `production_ready_claim=false`，不做 mirror/frontend/nginx/signer/object-storage/remote-dispatch/private-key/prod-ring 变更。当前 next task 是 `RC13-010`。
- `RC13-010` 已完成：新增 `scripts/project-rc13-declared-current-drift-zero.ps1`，生成 `.workflow/artifacts/rc13-declared-current-drift-zero/result.json`、`declared-current-drift-zero-reconciliation.json`、`drift-zero-denial.json`、`object-manifest-descriptor-binding-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-010-declared-current-drift-zero.json`。结果为 `passed`、9 checks、0 failed checks、71 comparisons、19 drift entries；当前 payload bytes 仍匹配 RC12 记录，但 drift-zero 继续 deny，包含 17 个 RC12 carry-forward drift 和 2 个 RC13 local trust gate drift；未 rewrite declared metadata、未 payload fetch、未 install、activation、rollback、support upload、recovery、remote dispatch、mirror/frontend/nginx/signer/object-storage/private-key 变更或 production mutation。当前 next task 是 `RC13-011`。
- `RC13-011` 已完成：新增 `scripts/project-rc13-object-manifest-descriptor-binding.ps1`，生成 `.workflow/artifacts/rc13-object-manifest-descriptor-binding/result.json`、`object-manifest-descriptor-binding.json`、`object-manifest-descriptor-denial.json`、`freshness-revocation-authority-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-011-object-manifest-descriptor-binding.json`。结果为 `passed`、9 checks、0 failed checks、36 comparisons、0 drift；当前 payload bytes、descriptor、initramfs manifest、payload checksum set、compatibility、rollback baseline 和 support/recovery references 本地一致，但因 declared/current drift-zero 仍为 false，authoritative binding、object trust、quarantine preflight、install、activation、rollback、support upload、recovery、remote dispatch 和 production mutation 继续 deny。当前 next task 是 `RC13-012`。
- `RC13-012` 已完成：新增 `scripts/project-rc13-freshness-revocation-authority.ps1`，生成 `.workflow/artifacts/rc13-freshness-revocation-authority/result.json`、`freshness-revocation-authority-binding.json`、`freshness-revocation-authority-denial.json`、`freshness-revocation-authority-fail-closed-matrix.json`、`quarantine-preflight-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-012-freshness-revocation-authority.json`。结果为 `passed`、9 checks、0 failed checks、20 comparisons、0 drift、14 fail-closed cases；public signature 和 revocation authority 已在不处理 private material 的前提下绑定，但 freshness window 仍未绑定，且 object trust 受 declared/current drift-zero 等 upstream gates 阻塞，所以 freshness/revocation authority、object trust、quarantine preflight、install、activation、rollback、support upload、recovery、remote dispatch 和 production mutation 继续 deny。当前 next task 是 `RC13-020`。
- `RC13-020` 已完成：新增 `scripts/project-rc13-quarantine-preflight.ps1`，生成 `.workflow/artifacts/rc13-quarantine-preflight/result.json`、`quarantine-preflight-report.json`、`quarantine-preflight-denial.json`、`quarantine-preflight-fail-closed-matrix.json`、`agentcore-planspec-readiness-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-020-quarantine-preflight.json`。结果为 `passed`、12 checks、0 failed checks、26 fail-closed cases；quarantine preflight 因 object trust / freshness gates 未满足而在 network 前 deny，payload interpretation、quarantine write、install、activation、rollback、support upload、recovery、remote dispatch 和 production mutation 均保持 disabled。当前 next task 是 `RC13-021`。
- `RC13-021` 已完成：新增 `scripts/project-rc13-agentcore-executable-planspec-readiness.ps1`，生成 `.workflow/artifacts/rc13-agentcore-executable-planspec-readiness/result.json`、`agentcore-planspec-readiness.json`、`agentcore-planspec-readiness-denial.json`、`agentcore-planspec-readiness-fail-closed-matrix.json`、`security-execution-allow-preconditions-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-021-agentcore-executable-planspec-readiness.json`。结果为 `passed`、8 checks、0 failed checks、16 fail-closed cases；quarantine evidence 和 release object identity 已 hash-bound 到 AgentCore PlanSpec candidate，但 verified quarantine preflight、target set、exact approval、audit sink、nonce、expiry、policy version 和 SecurityExecution allow gates 仍缺失，所以 PlanSpec 保持 non-executable，install、activation、rollback、support upload、recovery、remote dispatch 和 production mutation 继续 disabled。当前 next task 是 `RC13-022`。
- `RC13-022` 已完成：新增 `scripts/project-rc13-security-execution-allow-preconditions.ps1`，生成 `.workflow/artifacts/rc13-security-execution-allow-preconditions/result.json`、`security-execution-allow-preconditions.json`、`security-execution-allow-denial.json`、`security-execution-allow-fail-closed-matrix.json`、`two-target-identity-enrollment-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-022-security-execution-allow-preconditions.json`。结果为 `passed`、8 checks、0 failed checks、17 fail-closed cases；SecurityExecution allow、effect preparation、activation 和 rollback execution 按预期继续 denied，install、activation、rollback、support upload、recovery、remote dispatch、private signing material handling、mirror/frontend/nginx/signer/object-storage 变更和 production mutation 均保持 disabled。当前 next task 是 `RC13-030`。
- `RC13-030` 已完成：新增 `scripts/project-rc13-two-target-identity-enrollment.ps1`，生成 `.workflow/artifacts/rc13-two-target-identity-enrollment/result.json`、`target-identity-set.json`、`target-identity-enrollment-denial.json`、`target-identity-enrollment-fail-closed-matrix.json`、`exact-approval-audit-binding-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-030-two-target-identity-enrollment.json`。结果为 `passed`、10 checks、0 failed checks、16 fail-closed cases；activation authority 仍要求至少 2 个 distinct / fresh / compatible local canary identities，当前 enrolled target identity count 为 0，target identity enrollment、exact approval、activation、rollback、support upload、recovery、remote dispatch 和 production mutation 均保持 denied。当前 next task 是 `RC13-031`。
- `RC13-031` 已完成：新增 `scripts/project-rc13-exact-approval-audit-binding.ps1`，生成 `.workflow/artifacts/rc13-exact-approval-audit-binding/result.json`、`exact-approval-packet.json`、`approval-audit-binding-denial.json`、`exact-approval-fail-closed-matrix.json`、`controlled-activation-approval-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-031-exact-approval-audit-binding.json`。结果为 `passed`、10 checks、0 failed checks、22 fail-closed cases；approval packet 记录 actor、release、object digest、target set、AgentCore PlanSpec、SecurityExecution envelope、rollback baseline、support/recovery、audit sink、nonce、expiry 和 policy version 的绑定合同，但因 target identities、approval actor、approval signature、audit sink、nonce 和 expiry 仍未绑定，exact approval 和 activation 继续 denied；approval 不隐含 execution，remote dispatch 和 production mutation 均保持 disabled。当前 next task 是 `RC13-040`。
- `RC13-040` 已完成：新增 `scripts/project-rc13-controlled-activation.ps1`，生成 `.workflow/artifacts/rc13-controlled-activation/result.json`、`activation-gate-report.json`、`activation-denial-evidence.json`、`controlled-activation-rollback-handoff.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-040-controlled-activation.json`。结果为 `passed`、8 checks、0 failed checks、12 fail-closed cases；controlled activation gate 已评估并按预期 denied，因为 object trust、quarantine verification、target identity set、exact approval、audit sink、nonce、expiry、AgentCore executable PlanSpec 和 SecurityExecution allow gates 仍未满足；未伪造 activation audit，未 prepare / execute effect，未执行 activation、rollback、support upload、recovery、remote dispatch 或 production mutation。当前 next task 是 `RC13-041`。
- `RC13-041` 已完成：新增 `scripts/project-rc13-controlled-rollback-support-recovery.ps1`，生成 `.workflow/artifacts/rc13-controlled-rollback-support-recovery/result.json`、`rollback-planspec-requirement.json`、`rollback-support-recovery-gate-report.json`、`rollback-support-recovery-denial-evidence.json`、`support-recovery-evidence-chain.json`、`controlled-execution-support-bundle.json`、`recovery-reference-index.json` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-041-controlled-rollback-support-recovery.json`。结果为 `passed`、11 checks、0 failed checks、14 fail-closed cases；controlled rollback / support / recovery 按预期 denied，因为 controlled activation 未执行，separate rollback approval、rollback target identities、AgentCore rollback PlanSpec、SecurityExecution rollback allow、audit journal、post-rollback observations 和 remote fleet gates 仍缺失；support bundle 保持 redacted/local-only，未执行 rollback、support upload、recovery、remote dispatch、install、activation、private signing material handling、mirror/frontend/nginx/signer/object-storage 变更或 production mutation。当前 next task 是 `RC13-050`。
- `RC13-050` 已完成：新增 `scripts/run-rc13-final-closeout-audit.ps1`，生成 `.workflow/artifacts/rc13-final-closeout-audit/result.json`、`.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/FINAL-AUDIT-20260609-production-distro-rc13.json`、`.workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/final-rc13-closeout-summary.md` 和 `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-050-final-closeout-audit.json`。审计结论为 `PASS`、16 checks、0 blockers；RC13 作为 non-GA fail-closed AIOS-body milestone 关闭，仍保持 drift-zero、freshness window、object trust、quarantine preflight authority、AgentCore executable PlanSpec、SecurityExecution allow、two-target identity enrollment、exact approval、activation、rollback execution、support upload、recovery execution、remote dispatch、mirror/frontend/nginx/signer/object-storage/private-key authority 和 production ring mutation disabled；下一步进入 Production Distro RC14 planning。
- `RC14-000` 已完成：新增 `.workflow/active/WFS-20260609-agentos-production-distro-rc14/plan.json`、`workflow-session.json`、`.task/TASK-RC14-*.json`、`docs/rc14-local-execution-readiness-plan.md`、`evidence/RC14-000-planning.json` 和 `.workflow/.csv-wave/20260609-plan-rc14-local-execution-readiness/context.md` 规划会话。RC14 从 RC13 final audit blockers 出发，规划 drift-zero repair、freshness window and revocation binding、local object trust、verified quarantine preflight、AgentCore executable PlanSpec、SecurityExecution allow envelope、two-target local identity enrollment、exact approval execution binding、controlled activation、separate rollback support/recovery 和 final audit；仍保持 `production_ready_claim=false`，不做 mirror frontend / Nginx/TLS / remote signer / object storage provisioning / remote dispatch infrastructure / private signing material handling / production ring mutation。当前 next task 是 `RC14-001`。
- `RC5-001` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc5/plan.json`、`workflow-session.json`、`.task/TASK-RC5-001.json`、`docs/controlled-hosted-mirror-service-contract.md` 和 `evidence/RC5-001-controlled-hosted-mirror-service-contract.json`。契约冻结 `aios.w33d.xyz` hosted mirror service framework：远端 host `47.101.11.109` 只作为 metadata-only mirror framework，不存储大 release payload，不保存 private signing material，不提供 signing / activation / rollback / production ring mutation / remote dispatch / TUI authority；后续 `RC5-010` 才允许按该边界配置 nginx reverse proxy 和静态 mirror layout。
- `RC5-002` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc5/docs/user-install-update-channel-boundary.md`、`.task/TASK-RC5-002.json` 和 `evidence/RC5-002-user-install-update-channel-boundary.json`。用户侧 install/update 边界明确 mirror 只是 transport、不是 root of trust；bootstrap / updater 必须验证 schema、`production_ready_claim=false`、RC4 final audit hash、hosted transport hash、mirror publication hash、signature、revocation、freshness、content hashes 和 rollback baseline，任何缺失、过期、篡改、越权或大 payload 引用都 fail closed。
- `RC5-003` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc5/docs/hosted-mirror-service-threat-model.md`、`.task/TASK-RC5-003.json` 和 `evidence/RC5-003-hosted-mirror-service-threat-model.json`。威胁模型覆盖 DNS/routing misbinding、TLS downgrade、static root escape、metadata drift、secret/authority leak、authority broadening、storage exhaustion 和 stale cache；RC5 明确保持 non-GA，直到 TLS、hosted verifier、fail-closed fixtures、hosted signed-channel consumption、rollback execution drill、multi-node canary、support/recovery 和 storage policy 证据齐备。
- `RC5-010` 已完成：新增 `scripts/provision-rc5-hosted-mirror-service.ps1`，通过 SSH 在 `47.101.11.109` 上配置 metadata-only mirror root `/srv/aios-mirror` 和 nginx site `/etc/nginx/sites-available/aios.w33d.xyz`，并用 `curl --resolve aios.w33d.xyz:80:47.101.11.109` 验证 `http://aios.w33d.xyz/health.json`、`/.well-known/aios/mirror.json`、`/channel/index.json` 和 `/releases/README.txt`。结果 `.workflow/artifacts/rc5-hosted-mirror-service/result.json` 为 `passed`、10 checks、0 blockers；远端保持 metadata-only、large artifact storage deferred、无 signing / activation / rollback / active slot / production ring / remote dispatch / TUI authority，`tls_verified=false` 且 TLS 仍是 GA 前置门槛。
- `RC5-011` 已完成：新增 `scripts/verify-rc5-hosted-endpoint.ps1`，生成 `.workflow/artifacts/rc5-hosted-endpoint-verifier/result.json`，结果为 `passed`、17 checks、0 blockers。Verifier 使用 `curl --resolve` 不依赖本地 DNS，验证 health / mirror descriptor / channel index / release README 均可访问，channel index 绑定 RC4 final audit、hosted transport manifest 和 mirror publication hashes，`/releases/` directory listing 被 404 阻断，`POST /health.json` 被 403 阻断，endpoint 内容无 secret marker；TLS 仍记录为 GA gate。
- `RC5-012` 已完成：新增 `scripts/verify-rc5-hosted-metadata-fail-closed-fixtures.ps1`，生成 `.workflow/artifacts/rc5-hosted-metadata-fail-closed/result.json`，结果为 `passed`、14 个 negative cases 全部通过、0 blockers。负例覆盖 health/channel malformed JSON、bad schema、GA claim、signing / activation / TUI authority、secret marker、missing RC4 binding、hosted transport hash drift、stale metadata、large payload reference 和 entry activation；脚本只在内存构造负例，不修改远端 mirror。
- `RC5-013` 已完成：新增 `scripts/provision-rc5-mirror-frontend.ps1`，部署 `http://aios.w33d.xyz/` 静态 AIOS Mirror 前端，远端文件为 `/srv/aios-mirror/index.html`、`/srv/aios-mirror/assets/mirror.css` 和 `/srv/aios-mirror/assets/mirror.js`。前端零外部依赖，读取现有 health / descriptor / channel metadata，展示 channel、freshness、verification checks、directory table、RC4 hash bindings 和 canvas trust path；结果 `.workflow/artifacts/rc5-mirror-frontend/result.json` 为 `passed`、11 checks、0 blockers，且不引入 signing / activation / rollback / production ring / remote dispatch / TUI authority。
- `RC5-020` 已完成：新增 `scripts/project-rc5-user-release-channel.ps1`，发布 `http://aios.w33d.xyz/bootstrap/manifest.json` 和 `http://aios.w33d.xyz/channel/user-release.json`，并更新 `http://aios.w33d.xyz/channel/index.json` 引用这两个 metadata endpoint。结果 `.workflow/artifacts/rc5-user-release-channel/result.json` 为 `passed`、10 checks、0 blockers；用户侧 bootstrap metadata 已可见，但 install/update 仍 blocked，原因是 release payload storage、payload signatures、TLS GA gate、rollback execution drill 和 multi-node canary evidence 仍未完成。
- `RC5-021` 已完成：新增 `scripts/project-rc5-multi-node-canary-proof.ps1`，生成 `.workflow/artifacts/rc5-multi-node-canary-proof/result.json`、`multi-node-canary-plan-projection.json` 和 `rollback-readiness-projection.json`。结果为 `passed`、19 checks、0 blockers；它证明 hosted mirror / endpoint verifier / fail-closed / frontend / user release channel、RC4 staged rollout smoke、fleet authority 和 rollback baseline 已 hash-bound，且 rollback readiness 为 true；真实 multi-node canary 仍按设计 blocked，当前要求至少 2 个 canary target nodes、remote fleet execution、exact operator approval、payload/signature、rollback execution plan 和 TLS GA gate，未执行 activation、rollback、remote dispatch 或 production ring mutation。
- `RC5-022` 已完成：新增 `scripts/project-rc5-hosted-support-recovery.ps1`，发布并验证 `http://aios.w33d.xyz/support/index.json`、`/support/recovery.json`、`/support/README.txt`，并更新 `/channel/index.json` 引用 support metadata。结果 `.workflow/artifacts/rc5-hosted-support-recovery/result.json` 为 `passed`、19 checks、0 blockers；support/recovery 仍是 metadata-only、redacted、hash-bound projection，不开放 support upload endpoint，不执行 recovery / rollback / activation，不改 active slot / production ring / remote dispatch / TUI authority。
- `RC5-030` 已完成：新增 `scripts/run-rc5-final-closeout-audit.ps1`，生成 `.workflow/artifacts/rc5-final-closeout-audit/result.json`、`.workflow/active/WFS-20260608-agentos-production-distro-rc5/evidence/FINAL-AUDIT-20260608-production-distro-rc5.json` 和 `.workflow/active/WFS-20260608-agentos-production-distro-rc5/docs/final-rc5-closeout-summary.md`。审计结论为 `PASS`，16 checks、0 blockers，覆盖 hosted service、endpoint verifier、metadata fail-closed、mirror frontend、user release channel、canary proof、support/recovery 和 live hosted endpoints；RC5 仍不宣称 GA，RC6 规划聚焦 TLS、signed payload、installer/bootstrap、storage policy、真实 canary/rollback execution。
- `RC6-001` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc6/plan.json`、`workflow-session.json`、`docs/installable-signed-payload-channel-contract.md`、`.task/TASK-RC6-001.json` 和 `evidence/RC6-001-installable-signed-payload-channel-contract.json`。契约定义 `/payloads/index.json`、payload manifest/checksum/signature metadata、`/install/bootstrap.json`、installer verification inputs 和 fail-closed cases；RC6 初始仍只允许 payload metadata，不允许在有限 mirror 主机上存储大 payload，不执行 install / activation / rollback / production ring mutation / support upload / remote dispatch / TUI authority。
- `RC6-002` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/bootstrap-installer-consumption-boundary.md`、`.task/TASK-RC6-002.json` 和 `evidence/RC6-002-bootstrap-installer-consumption-boundary.json`。边界定义 installer states、验证顺序、allowed preflight outputs、approval binding 和 fail-closed cases；RC6 最多到 `install-preflight-ready`，不宣称 `install-authorized` 或 `installed`，禁止 active rootfs install、boot metadata mutation、active slot mutation、A/B activation、rollback execution、production ring mutation、support upload、private signing material read、remote dispatch、TUI / model / shell authority。
- `RC6-003` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/tls-storage-signed-payload-threat-model.md`、`.task/TASK-RC6-003.json` 和 `evidence/RC6-003-tls-storage-signed-payload-threat-model.json`。威胁模型冻结 TLS/DNS、Nginx static root、metadata size policy、signed payload placeholder/revocation/signature binding 和 frontend UX 边界；HTTP metadata 仍只能是 candidate data，TLS 是 GA gate，远端不能签名、安装、激活、回滚、上传 support、远程执行或授予 TUI / shell / model authority。
- `RC6-004` 已完成：新增 `scripts/provision-rc6-mirror-portal.ps1`，部署并验证 `http://aios.w33d.xyz/` RC6 mirror portal、`/payloads/index.json`、`/payloads/aios/production-distro-rc6-metadata-preview/{manifest,checksums,signatures}.json` 和 `/install/bootstrap.json`。结果 `.workflow/artifacts/rc6-mirror-portal/result.json` 为 `passed`、16 checks、0 blockers；前端零外部依赖，Nginx 阻断写方法和目录列表，payload 仍是 metadata-only / `verification-blocked`，signature 未发布，install / activation / rollback / support upload / remote dispatch / production ring / TUI authority 全部为 false。
- `RC6-010` 已完成：新增 `scripts/project-rc6-installable-payload-manifest.ps1`，从当前 release provenance、release channel metadata、RC1 installable media、RC5 final audit、RC6 contracts 和 RC6 mirror portal 结果投影 `.workflow/artifacts/rc6-installable-payload-manifest/{payload-manifest,payload-checksums,payload-signatures,payload-index,result}.json`。结果为 `passed`、46 checks、0 blockers；记录 3 个 declared/current hash drift（`update_metadata`、`release_channel_metadata`、`qemu_runtime_smoke`），因此 payload 继续 `verification-blocked`，large payload storage、signature、install、activation、rollback、remote dispatch、production ring 和 TUI authority 均未开放。
- `RC6-011` 已完成：新增 `scripts/publish-rc6-hosted-payload-metadata.ps1`，把 RC6-010 current-artifacts payload metadata 发布到 `http://aios.w33d.xyz/payloads/index.json`、`/payloads/aios/production-distro-rc6-current-artifacts/{manifest,checksums,signatures}.json`，并同步 `/install/bootstrap.json` 和 `/channel/index.json`。结果 `.workflow/artifacts/rc6-hosted-payload-metadata/result.json` 为 `passed`、17 checks、0 blockers；远端仍 metadata-only，signature 未发布，install/activation/rollback/support upload/remote dispatch/production ring/TUI authority 全部为 false，目录 listing 和 POST 均被阻断。
- `RC6-012` 已完成：新增 `scripts/verify-rc6-signed-payload-fail-closed-fixtures.ps1`，基于 RC6-011 hosted payload metadata 做本地负例验证，覆盖 bad schema、GA claim、manifest/checksum/signature hash mismatch、missing/placeholder signature、mirror signing authority、missing/revoked/stale revocation、large payload policy、drift not blocking、missing rollback/compatibility、payload/manifest/install/channel authority broadening 等 21 个 case。结果 `.workflow/artifacts/rc6-signed-payload-fail-closed/result.json` 为 `passed`、21/21 cases blocked、0 blockers；不修改远端、不签名、不安装、不激活、不回滚。
- `RC6-020` 已完成：新增 `scripts/project-rc6-bootstrap-installer-preflight.ps1`，用 `curl --resolve aios.w33d.xyz:80:47.101.11.109` 拉取线上 health / descriptor / channel / install / payload / support metadata 并生成 `.workflow/artifacts/rc6-bootstrap-installer-preflight/preflight-report.json`。结果 `.workflow/artifacts/rc6-bootstrap-installer-preflight/result.json` 为 `passed`、6 checks、0 task blockers；preflight state 为 `verification-blocked`，4 个预期 blockers 是缺 signature/signed metadata、revocation snapshot、installer compatibility contract 和 rollback baseline；未执行 install/activation/rollback/dispatch。
- `RC6-021` 已完成：新增 `scripts/verify-rc6-installer-fail-closed.ps1`，基于 RC6-020 preflight、RC6-011 hosted payload metadata 和 RC6-010 payload manifest 做本地 installer fail-closed 负例验证。结果 `.workflow/artifacts/rc6-installer-fail-closed/result.json` 为 `passed`、5 checks、0 blockers、12/12 cases passed，覆盖 unsigned、stale、revoked、oversized、large payload URL、manifest hash mismatch 和 install authority broadening；所有 case 都保持 `verification-blocked`，未执行 install/activation/rollback/active slot/production ring/support upload/remote dispatch/TUI authority。
- `RC6-022` 已完成：新增 `scripts/provision-rc6-mirror-frontend-refresh.ps1`，刷新 `http://aios.w33d.xyz/` AIOS public mirror 前端和 nginx 只读静态站配置，远端文件为 `/srv/aios-mirror/index.html`、`/srv/aios-mirror/assets/mirror.css`、`/srv/aios-mirror/assets/mirror.js` 和 `/etc/nginx/sites-available/aios.w33d.xyz`。结果 `.workflow/artifacts/rc6-mirror-frontend-refresh/result.json` 为 `passed`、16 checks、0 blockers；前端展示 payload/install/support/verification/directory/hash binding/canvas trust path，零外部依赖，并证明 health、descriptor、channel、payload、install、support metadata hash 前后保持一致，current payload 仍是 `production-distro-rc6-current-artifacts` / `verification-blocked`，目录 listing 和 POST 继续阻断。
- `RC6-030` 已完成：新增 `scripts/project-rc6-canary-execution-packet.ps1`，生成 `.workflow/artifacts/rc6-canary-execution-packet/result.json`、`canary-execution-packet.json` 和 `rollback-execution-preconditions.json`。结果为 `passed`、13 checks、0 blockers；packet 绑定 RC5 canary proof、RC5 rollback readiness、RC6 hosted payload metadata、RC6 preflight、RC6 installer fail-closed、RC6 mirror frontend refresh、fleet rollout authority 和 live endpoint hashes；仍保持 `canary_execution_allowed=false`、`canary_execution_performed=false`、`rollback_execution_performed=false`，当前 blocker 是 payload signature/revocation/installer compatibility/rollback baseline、2+ canary nodes、remote fleet execution、exact approval 和 TLS GA gate。
- `RC6-031` 已完成：新增 `scripts/project-rc6-rollback-execution-preconditions.ps1`，生成 `.workflow/artifacts/rc6-rollback-execution-preconditions/result.json`、`rollback-drill-precondition-matrix.json` 和 `rollback-execution-blockers.json`。结果为 `passed`、12 checks、0 blockers；matrix 绑定 RC6 canary packet、RC6 rollback preconditions、RC5 rollback readiness、RC4 rollback drill projection、RC5 hosted support/recovery、RC6 hosted payload metadata、RC6 bootstrap preflight、RC6 installer fail-closed、RC6 mirror frontend refresh 和 live endpoint hashes；rollback readiness 为 true，但 `rollback_execution_allowed=false`、`rollback_execution_performed=false`、`canary_execution_allowed=false`，剩余执行 blocker 是 payload signature、revocation snapshot、installer compatibility、rollback baseline publication、SecurityExecutionEngine rollback PlanSpec approval、canary activation evidence、multi-node canary targets、remote fleet execution、exact approval 和 TLS GA gate。
- `RC6-040` 已完成：新增 `scripts/run-rc6-final-closeout-audit.ps1`，生成 `.workflow/artifacts/rc6-final-closeout-audit/result.json`、`.workflow/active/WFS-20260608-agentos-production-distro-rc6/evidence/FINAL-AUDIT-20260608-production-distro-rc6.json` 和 `.workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/final-rc6-closeout-summary.md`。审计结论为 `PASS`、19 checks、0 blockers，覆盖 RC6 contracts、hosted payload metadata、signed payload fail-closed、bootstrap installer preflight、installer fail-closed、mirror frontend refresh、canary packet、rollback preconditions 和 live RC6 endpoints；RC6 仍不宣称 GA，RC7 规划聚焦 signed metadata、revocation snapshot、installer compatibility contract、rollback baseline publication、TLS evidence、2+ canary targets、exact-approved canary 和 rollback drills。
- `RC7-001` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc7/plan.json`、`workflow-session.json`、`docs/signed-payload-consumption-controlled-execution-contract.md`、`.task/TASK-RC7-001.json` 和 `evidence/RC7-001-signed-payload-consumption-controlled-execution-contract.json`。合同冻结 signed payload consumption state machine、`sign.w33d.xyz` external signer boundary、installer verification boundary、controlled canary/rollback execution boundary 和 fail-closed cases；本 task 未读取私钥、未签名、未安装、未激活、未回滚、未改 active slot / production ring，下一步是 `RC7-002` 发布 signed metadata 与 revocation snapshot projection。
- `RC7-002` 已完成：新增 `scripts/publish-rc7-signed-metadata-revocation.ps1`，生成并发布 `.workflow/artifacts/rc7-signed-metadata-revocation/{signature-claims,signed-metadata,revocation-snapshot,payload-signatures-after-rc7,hosted-payload-index-after-signed-metadata,install-bootstrap-after-signed-metadata,hosted-channel-index-after-signed-metadata,result}.json`，并写入 `.task/TASK-RC7-002.json` 与 `evidence/RC7-002-signed-metadata-revocation.json`。结果为 `passed`、20 checks、0 blockers；远端新增/更新 `/payloads/aios/production-distro-rc6-current-artifacts/{signatures,signed-metadata,revocations}.json`、`/payloads/index.json`、`/install/bootstrap.json` 和 `/channel/index.json`，使用 `curl --resolve` 验证 200、hash binding 匹配、目录 listing 404、POST 403；当前仍是 `verification-blocked`，`cryptographic_signature_present=false`、`signature_available=false`、`install_allowed=false`、`activation_allowed=false`、`rollback_execution_allowed=false`、`production_ready_claim=false`。
- `RC7-003` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc7/docs/installer-compatibility-rollback-baseline-contract.md`、`.task/TASK-RC7-003.json` 和 `evidence/RC7-003-installer-compatibility-rollback-baseline-contract.json`。合同定义 `/install/compatibility.json` 与 `/install/rollback-baseline.json` 的 schema、hash binding、state transitions 和 fail-closed cases，绑定 RC6 preflight 中的 compatibility / rollback baseline blockers 与 RC6 rollback baseline readiness；本 task 不发布新远端 endpoint，不安装、不激活、不回滚、不改 active slot / production ring，下一步是 `RC7-010` 基于 RC7 Wave 0 合同投影 installer signed metadata consumption report。
- `RC7-010` 已完成：新增 `scripts/project-rc7-installer-signed-consumption.ps1`，通过 `curl --resolve aios.w33d.xyz:80:47.101.11.109` 只读拉取线上 `/channel/index.json`、`/install/bootstrap.json`、`/payloads/index.json`、payload manifest/checksums/signatures、`signed-metadata.json` 和 `revocations.json`，生成 `.workflow/artifacts/rc7-installer-signed-consumption/result.json` 与 `consumption-report.json`。结果为 `passed`、12 checks、0 task blockers，installer 仍 `verification-blocked`、7 个 installer blockers：hosted byte-hash canonicalization、缺真实 cryptographic signature、缺 `/install/compatibility.json` 发布与 hash binding、缺 `/install/rollback-baseline.json` 发布与 hash binding、storage/drift 未解决、TLS gate、exact approval 未给出；本 task 不签名、不安装、不激活、不回滚、不改 active slot / production ring，下一步是 `RC7-011` signed consumption fail-closed fixtures。
- `RC7-011` 已完成：新增 `scripts/verify-rc7-signed-consumption-fail-closed.ps1` 和 `.workflow/artifacts/rc7-signed-consumption-fail-closed/result.json`。结果为 `passed`、5 checks、0 blockers、21/21 negative cases passed；覆盖 missing / mismatched signed metadata、signature claim mismatch、missing / revoked / stale revocation、缺真实 cryptographic signature、mirror signing authority、compatibility / rollback baseline missing/schema/hash mismatch、production-ready claim、payload / remote dispatch / TUI authority broadening、storage/drift、TLS 和 exact approval 缺失；所有 case 均保持 `verification-blocked`，不远端发布、不签名、不安装、不激活、不回滚。
- `RC7-012` 已完成：新增 `scripts/publish-rc7-install-rollback-baseline.ps1`，发布并验证 `http://aios.w33d.xyz/install/compatibility.json`、`/install/rollback-baseline.json`，并更新 `/payloads/index.json`、`/install/bootstrap.json` 和 `/channel/index.json` 的 compatibility / rollback baseline hash bindings。结果 `.workflow/artifacts/rc7-install-rollback-baseline/result.json` 为 `passed`、14 checks、0 blockers；线上新 endpoint 200，目录 listing 404、POST 403，install/activation/rollback 仍为 false；剩余 blocker 是 prior signed metadata byte-hash canonicalization、缺真实 cryptographic signature、storage/drift、TLS 和 exact approval。
- `RC7-020` 已完成：新增 `scripts/provision-rc7-mirror-frontend-signed-status.ps1`，刷新并验证 `http://aios.w33d.xyz/` public mirror frontend，远端静态文件为 `/srv/aios-mirror/index.html`、`/srv/aios-mirror/assets/mirror.css` 和 `/srv/aios-mirror/assets/mirror.js`。结果 `.workflow/artifacts/rc7-mirror-frontend-signed-status/result.json` 为 `passed`、15 checks、0 blockers；前端展示 signed metadata、revocation snapshot、compatibility、rollback baseline 和 non-GA install-blocked 状态，验证使用 `curl --resolve aios.w33d.xyz:80:47.101.11.109`，metadata endpoint byte hashes 保持不变，目录 listing 404、POST 403，未签名、未上传 payload、未安装、未激活、未回滚、未改 active slot / production ring、未开启 support upload / remote dispatch / TUI authority。
- `RC7-021` 已完成：新增 `scripts/provision-rc7-tls-nginx-hardening.ps1`，为 `aios.w33d.xyz` 配置 HTTPS mirror endpoint 并记录 nginx hardening evidence。结果 `.workflow/artifacts/rc7-tls-nginx-hardening/result.json` 为 `passed`、12 checks、0 blockers；HTTPS root / health / channel / payload / install / compatibility / rollback baseline 均为 200，证书 subject 为 `CN = aios.w33d.xyz`，有效期到 2026-09-06，HTTPS 响应包含 HSTS / nosniff / referrer / frame / CSP / AIOS mirror headers，nginx server tokens 不暴露版本，payload directory listing 404，HTTP/HTTPS POST 403；HTTP 保持只读兼容，HTTPS 成为 preferred endpoint，install/activation/rollback/production_ready_claim 仍为 false，未读取或输出私钥内容。
- `RC7-022` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc7/docs/large-payload-storage-policy.md`，冻结大 payload 存储与外部 object storage 边界。策略明确 `47.101.11.109` 继续 metadata-only，不在 `/srv/aios-mirror` 存 ISO / disk image / rootfs / update bundle / recovery image，不开放 upload endpoint；大 payload bytes 只能作为 immutable HTTPS object descriptor 引用，必须绑定 size、sha256、manifest、checksums、signed metadata、revocation、compatibility、rollback baseline 和 policy version；object storage 只是 transport，installer 必须 quarantine download 后本地验 byte digest，任何 credential-bearing URL、mutable URL、hash mismatch、stale metadata、缺签名/吊销/兼容/回滚基线都 fail closed。下一步回到 AIOS 本体执行链：`RC7-030` canary targets and exact approval packet。
- `RC7-030` 已完成：新增 `scripts/project-rc7-multi-node-canary-approval.ps1`，生成 `.workflow/artifacts/rc7-multi-node-canary-approval/result.json`、`canary-target-set.json` 和 `exact-approval-packet.json`。结果为 `passed`、12 checks、0 blockers；packet 绑定 RC7 signed consumption、fail-closed fixtures、rollback baseline、mirror frontend、TLS、large payload storage policy、RC6 canary/rollback preconditions 和 fleet rollout authority evidence，并用 HTTPS live metadata hash 绑定当前 `production-distro-rc6-current-artifacts`。本 task 只投影 approval packet，不执行 canary / activation / rollback；当前仍要求 2+ canary target nodes、真实 cryptographic signature、remote fleet execution、exact operator approval、AgentCore PlanSpec 和 SecurityExecutionEngine approval，且不签名、不上传 payload、不安装、不激活、不回滚、不改 active slot / production ring、不开放 support upload / remote dispatch / TUI authority。下一步是 `RC7-031` gated canary activation evidence。
- `RC7-031` 已完成：新增 `scripts/project-rc7-gated-canary-activation.ps1`，生成 `.workflow/artifacts/rc7-gated-canary-activation/result.json`、`activation-gate-report.json` 和 `activation-denial-evidence.json`。结果为 `passed`、11 checks、0 blockers；gate report 证明 signed metadata、revocation、compatibility、rollback baseline、TLS 和 storage policy 已可见，并且 HTTPS live metadata hash 与 `RC7-030` approval packet 绑定一致；但真实 cryptographic signature、2+ canary target nodes、remote fleet execution、exact operator approval、AgentCore PlanSpec 和 SecurityExecutionEngine approval 均未满足，因此 `activation_allowed=false`、`activation_performed=false`。本 task 不签名、不上传 payload、不安装、不激活、不回滚、不改 active slot / production ring、不开放 support upload / remote dispatch / TUI authority。下一步是 `RC7-032` gated rollback drill evidence。
- `RC7-032` 已完成：新增 `scripts/project-rc7-gated-rollback-drill.ps1`，生成 `.workflow/artifacts/rc7-gated-rollback-drill/result.json`、`rollback-drill-gate-report.json` 和 `rollback-drill-denial-evidence.json`。结果为 `passed`、11 checks、0 blockers；gate report 证明 signed metadata、revocation、compatibility、rollback baseline、support/recovery metadata 和 TLS 已可见，rollback readiness 为 true，但真实 cryptographic signature、canary activation execution、2+ canary target nodes、remote fleet execution、exact operator approval、AgentCore rollback PlanSpec 和 SecurityExecutionEngine rollback approval 均未满足，因此 `rollback_execution_allowed=false`、`rollback_execution_performed=false`。本 task 不签名、不上传 payload、不安装、不激活、不回滚、不改 boot / active slot / persistent state / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。下一步是 `RC7-040` final audit and next milestone planning。
- `RC7-040` 已完成：新增 `scripts/run-rc7-final-closeout-audit.ps1`，生成 `.workflow/artifacts/rc7-final-closeout-audit/result.json`、`.workflow/active/WFS-20260608-agentos-production-distro-rc7/evidence/FINAL-AUDIT-20260608-production-distro-rc7.json` 和 `.workflow/active/WFS-20260608-agentos-production-distro-rc7/docs/final-rc7-closeout-summary.md`。审计结论为 `PASS`、19 checks、0 blockers，覆盖 signed metadata / revocation、installer signed consumption、signed consumption fail-closed、compatibility / rollback baseline、mirror frontend、TLS、large payload storage policy、multi-node canary approval、gated activation、gated rollback 和 HTTPS live metadata；RC7 仍不宣称 GA，下一轮 RC8 规划聚焦 real installable payload bytes、public signature artifact ingestion、installer VM smoke、exact-approved canary activation 和 rollback drill execution under AgentCore + SecurityExecutionEngine。
- `RC8-001` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc8/plan.json`、`workflow-session.json`、`docs/real-installable-payload-controlled-execution-contract.md`、`.task/TASK-RC8-001.json` 和 `evidence/RC8-001-real-installable-payload-controlled-execution-contract.json`。合同冻结 real installable payload bytes、immutable object descriptor、public signature artifact ingestion、installer VM smoke、controlled canary/rollback execution smoke 和 fail-closed cases；RC8 仍保持 `production_ready_claim=false`，不读取私钥、不签名、不上传大 payload 到 mirror、不安装、不激活、不回滚、不改 boot / active slot / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。下一步是 `RC8-002` immutable payload object descriptor and byte boundary。
- `RC8-002` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc8/docs/immutable-payload-object-descriptor-contract.md`、`.task/TASK-RC8-002.json` 和 `evidence/RC8-002-immutable-payload-object-descriptor-boundary.json`，并更新 RC8 plan/session/state。合同定义 `agentos.payload-object-descriptor.v1` 必填字段、禁止 credential-bearing / mutable / non-HTTPS / authority-bearing descriptor 内容、byte quarantine 下载边界、descriptor publication boundary 和 fail-closed cases；本 task 未发布 descriptor、未下载 payload bytes、未上传大 payload、未签名、未安装、未激活、未回滚、未改 boot / active slot / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。下一步是 `RC8-003` public signature artifact ingestion and receipt boundary。
- `RC8-003` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc8/docs/public-signature-artifact-ingestion-contract.md`、`.task/TASK-RC8-003.json` 和 `evidence/RC8-003-public-signature-artifact-ingestion-boundary.json`，并更新 RC8 plan/session/state。合同定义 `agentos.public-signature-artifact.v1` public signature artifact 字段、receipt 字段、canonical payload binding、publication rules 和 fail-closed cases；签名接入只能读取 public artifacts 和 descriptor，不读取私钥、不生成签名、不让 signer / mirror 获得 install、activation、rollback、support upload、remote dispatch、TUI、shell 或 model authority。下一步是 `RC8-010` real installable payload object descriptor projection。
- `RC8-010` 已完成：新增 `scripts/project-rc8-real-payload-object-descriptor.ps1`，生成 `.workflow/artifacts/rc8-real-payload-object-descriptor/result.json`、`payload-object-descriptor.json`、`payload-object-checksums.json` 和 `descriptor-report.json`，并写入 `.workflow/active/WFS-20260608-agentos-production-distro-rc8/.task/TASK-RC8-010.json` 与 `evidence/RC8-010-real-payload-object-descriptor.json`。结果为 `passed`、9 checks、0 task blockers；descriptor 绑定真实本地 payload bytes `image/out/agentos-initramfs.cpio.gz` 的 size 和 SHA-256，且与 `image/out/agentos-initramfs.manifest.json` 一致。payload surface 仍是 `candidate-verification-blocked`，原因是 external HTTPS object URI 未发布、public signature artifact 未接入、installer VM smoke 未跑、RC6 declared/current drift 未 reconciliation；本 task 未上传 payload、未下载 payload、未签名、未安装、未激活、未回滚、未改 boot / active slot / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。下一步是 `RC8-011` public signature artifact ingestion。
- `RC8-011` 已完成：新增 `scripts/project-rc8-public-signature-ingestion.ps1`，读取 `image/out/agentos-initramfs.cpio.gz.prod.sig.json` 作为 public detached signature，生成 `.workflow/artifacts/rc8-public-signature-ingestion/result.json`、`signature-ingestion-receipt.json` 和 `public-signature-artifact-summary.json`，并写入 `.task/TASK-RC8-011.json` 与 `evidence/RC8-011-public-signature-ingestion.json`。结果为 `passed`、12 checks、0 task blockers；signature artifact 与 RC8 descriptor 的 target path、object hash、canonical payload hash、revocation status 和 packaged public key crypto verification 均通过；receipt 只保留 signature value hash 并 redacted public identity。payload 仍未授权 install / activation / rollback，剩余 blockers 是 external HTTPS object URI 未发布、installer VM smoke 未跑、declared/current drift 未 reconciliation；本 task 不读取私钥、不生成签名、不上传 payload、不安装、不激活、不回滚、不开放 support upload / remote dispatch / TUI authority。下一步是 `RC8-012` signed object descriptor fail-closed fixtures。
- `RC8-012` 已完成：新增 `scripts/verify-rc8-signed-object-descriptor-fail-closed.ps1`，生成 `.workflow/artifacts/rc8-signed-object-descriptor-fail-closed/result.json`，并写入 `.task/TASK-RC8-012.json` 与 `evidence/RC8-012-signed-object-descriptor-fail-closed.json`。结果为 `passed`、5 checks、34/34 cases、0 blockers；负例覆盖 bad descriptor schema、GA claim、HTTP / credential URI、mutable descriptor、missing size、object id mismatch、source artifact hash mismatch、missing required hashes、expired descriptor、signature target / object / canonical hash mismatch、missing / invalid signature、unknown algorithm / key id、missing / revoked / stale revocation、stale freshness、receipt descriptor / object / canonical hash mismatch、receipt crypto false、raw public identity leak、raw signature value leak、install / signer / TUI authority broadening。所有 case 都保持 `verification-blocked`，未发布远端、未上传/下载 payload、未安装、未激活、未回滚、未改 boot / active slot / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。当前剩余 payload blockers 是 external HTTPS object URI 未发布、installer VM smoke 未跑、declared/current drift 未 reconciliation；下一步是 `RC8-020` installer VM preflight and quarantined object-fetch smoke。
- `RC8-020` 已完成：新增 `scripts/project-rc8-installer-vm-preflight.ps1`，生成 `.workflow/artifacts/rc8-installer-vm-preflight/result.json`、`preflight-report.json`、`object-fetch-report.json`，并记录 QEMU boot smoke result / dependency evidence，写入 `.task/TASK-RC8-020.json` 与 `evidence/RC8-020-installer-vm-preflight.json`。结果为 `passed`、10 checks、7 preflight steps、1 preflight blocker；QEMU boot smoke 在 `microvm` 上观察到 required runtime markers，booted initramfs SHA-256 与 RC8 descriptor object digest 一致；repo-local payload bytes 已复制到 strict quarantine child path 并完成 size / digest 校验。真实 external HTTPS object fetch 仍 blocked，因为 descriptor URI 还不是外部 HTTPS object URI；本 task 未发布远端、未上传 payload、未远程下载 payload、未安装、未激活、未回滚、未改 boot / active slot / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。当前剩余 payload blockers 是 external HTTPS object URI 未发布和 declared/current drift 未 reconciliation；下一步是 `RC8-021` installer byte, signature, storage, and compatibility fail-closed fixtures。
- `RC8-021` 已完成：新增 `scripts/verify-rc8-installer-byte-fail-closed.ps1`，生成 `.workflow/artifacts/rc8-installer-byte-fail-closed/result.json`，并写入 `.task/TASK-RC8-021.json` 与 `evidence/RC8-021-installer-byte-fail-closed.json`。结果为 `passed`、6 checks、28/28 cases、0 blockers；负例覆盖 payload size / digest mismatch、quarantine path escape、remote download before external URI、HTTP / credential object URI、mutable descriptor、descriptor authority broadening、signature ingestion / crypto / descriptor binding / canonical payload binding / revocation failure、receipt descriptor / object / crypto mismatch、raw public identity leak、raw signature value leak、missing compatibility / rollback baseline / revocation snapshot / signed metadata、installer VM smoke missing、preflight-ready without external object、storage authority broadening 和 installer side-effect authority broadening。所有 case 均保持 `verification-blocked`，未发布远端、未上传 payload、未远程下载 payload、未安装、未激活、未回滚、未改 boot / active slot / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。当前剩余 payload blockers 是 external HTTPS object URI 未发布和 declared/current drift 未 reconciliation；下一步是 `RC8-022` mirror metadata and frontend consistency refresh。
- `RC8-022` 已完成：新增 `scripts/provision-rc8-mirror-consistency-refresh.ps1`，发布并验证 HTTPS mirror 上的 RC8 metadata-only payload index、install bootstrap、channel index、mirror status、object descriptor、signature receipt / summary、installer VM preflight、preflight report、object-fetch report、installer fail-closed result 和新版 `AIOS RC8 Mirror` 前端，生成 `.workflow/artifacts/rc8-mirror-consistency-refresh/result.json` 与本地 frontend/metadata artifacts，并写入 `.task/TASK-RC8-022.json` 与 `evidence/RC8-022-mirror-consistency-refresh.json`。结果为 `passed`、20 checks、0 blockers；验证使用 `curl --resolve aios.w33d.xyz:443:47.101.11.109`，HTTPS root 和 RC8 metadata endpoints 均为 200，hash bindings 与本地 artifacts 一致，health / mirror descriptor / compatibility / rollback baseline / support metadata byte hash 保持不变，payload directory listing 404，POST 403。镜像仍是 metadata-only，不托管 payload bytes、不发布 external object URI、不安装、不激活、不回滚、不改 boot / active slot / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority；下一步是 `RC8-030` exact-approved canary activation smoke under AgentCore and SecurityExecutionEngine。
- `RC8-030` 已完成：新增 `scripts/project-rc8-exact-approved-canary-smoke.ps1`，生成 `.workflow/artifacts/rc8-exact-approved-canary-smoke/result.json`、`canary-target-set.json`、`exact-approval-packet.json`、`activation-smoke-gate-report.json` 和 `activation-denial-evidence.json`，并写入 `.task/TASK-RC8-030.json` 与 `evidence/RC8-030-exact-approved-canary-smoke.json`。结果为 `passed`、15 checks、0 blockers；packet 绑定 RC8 descriptor、public signature receipt / summary、signed descriptor fail-closed、installer VM preflight、installer byte fail-closed、mirror consistency refresh、live HTTPS metadata 和 fleet rollout authority。激活按预期 `activation_allowed=false`，剩余执行 blockers 是 external HTTPS object URI 未发布、declared/current artifact drift 未 reconciliation、canary target 不足 2 个、remote fleet execution 未开启、exact operator approval 未授予、AgentCore PlanSpec 未绑定、SecurityExecutionEngine approval 未绑定；本 task 未签名、未上传 payload、未远程下载 payload、未安装、未激活、未回滚、未改 boot / active slot / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。下一步是 `RC8-031` controlled rollback drill through AgentCore rollback PlanSpec and SecurityExecutionEngine gates。
- `RC8-031` 已完成：新增 `scripts/project-rc8-controlled-rollback-drill.ps1`，生成 `.workflow/artifacts/rc8-controlled-rollback-drill/result.json`、`rollback-planspec-requirement.json`、`rollback-drill-gate-report.json` 和 `rollback-drill-denial-evidence.json`，并写入 `.task/TASK-RC8-031.json` 与 `evidence/RC8-031-controlled-rollback-drill.json`。结果为 `passed`、11 checks、0 blockers；rollback readiness 为 true，但按预期 `rollback_execution_allowed=false`、`rollback_execution_performed=false`。剩余 rollback blockers 是 external HTTPS object URI 未发布、declared/current artifact drift 未 reconciliation、canary activation evidence 未执行、canary target 不足 2 个、remote fleet execution 未开启、exact operator approval 未授予、AgentCore rollback PlanSpec 未绑定、SecurityExecutionEngine rollback approval 未绑定；本 task 未签名、未上传 payload、未远程下载 payload、未安装、未激活、未回滚、未改 boot / active slot / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。下一步是 `RC8-032` bind support and recovery evidence to the RC8 controlled execution smoke。
- `RC8-032` 已完成：新增 `scripts/project-rc8-controlled-execution-support-recovery.ps1`，生成 `.workflow/artifacts/rc8-controlled-execution-support-recovery/result.json`、`support-recovery-evidence-chain.json`、`controlled-execution-support-bundle.json` 和 `recovery-reference-index.json`，并写入 `.task/TASK-RC8-032.json` 与 `evidence/RC8-032-controlled-execution-support-recovery.json`。结果为 `passed`、11 checks、0 blockers；它把 RC8 activation denial、rollback denial、rollback PlanSpec requirement、mirror metadata、compatibility、rollback baseline 和 live support/recovery metadata 绑定成 redacted local support projection。support upload、recovery execution、activation、rollback execution 均按预期为 false；本 task 未签名、未上传 payload、未远程下载 payload、未安装、未激活、未回滚、未改 boot / active slot / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。已由 `RC8-040` Production Distro RC8 final closeout audit 收口。
- `RC8-040` 已完成：新增 `scripts/run-rc8-final-closeout-audit.ps1`，生成 `.workflow/artifacts/rc8-final-closeout-audit/result.json`、`.workflow/active/WFS-20260608-agentos-production-distro-rc8/evidence/FINAL-AUDIT-20260608-production-distro-rc8.json` 和 `.workflow/active/WFS-20260608-agentos-production-distro-rc8/docs/final-rc8-closeout-summary.md`，并写入 `.task/TASK-RC8-040.json` 与 `evidence/RC8-040-final-closeout-audit.json`。审计结论为 `PASS`、19 checks、0 blockers，覆盖 real payload descriptor、public signature ingestion、signed descriptor fail-closed、installer VM preflight、installer byte fail-closed、HTTPS mirror consistency、canary activation denial、rollback denial、support/recovery binding 和 live RC8 metadata；RC8 仍不宣称 GA，payload 保持 `verification-blocked`，下一轮 RC9 聚焦 external object storage、declared/current drift reconciliation、2+ canary targets、exact operator approval、AgentCore PlanSpec、SecurityExecutionEngine approval、controlled canary activation 和 rollback drill execution。
- `RC9-001` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc9/plan.json`、`workflow-session.json`、`docs/external-object-storage-controlled-canary-contract.md`、`.task/TASK-RC9-001.json` 和 `evidence/RC9-001-external-object-storage-controlled-canary-contract.json`。合同冻结 external immutable object storage、declared/current artifact drift reconciliation、two-node canary enrollment、exact approval、AgentCore PlanSpec binding、SecurityExecutionEngine approval binding、controlled activation、controlled rollback 和 fail-closed cases；本 task 未发布 external object URL、未上传 payload、未远程下载 payload、未签名、未安装、未激活、未回滚、未改 boot / active slot / persistent state / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。下一步是 `RC9-002` external object descriptor publication and artifact drift reconciliation contract。
- `RC9-002` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc9/docs/external-object-descriptor-drift-reconciliation-contract.md`、`.task/TASK-RC9-002.json` 和 `evidence/RC9-002-external-object-descriptor-drift-reconciliation-contract.json`，并更新 RC9 plan/session/state。合同定义 external immutable HTTPS object descriptor publication inputs/schema、mirror metadata-only publication boundary、declared/current artifact drift reconciliation comparisons/states、installer handoff boundary 和 fail-closed cases；本 task 未发布 external object URL、未上传 payload、未远程下载 payload、未签名、未安装、未激活、未回滚、未改 boot / active slot / persistent state / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。下一步是 `RC9-003` exact approval target enrollment AgentCore and SecurityExecution binding contract。
- `RC9-003` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc9/docs/controlled-execution-binding-contract.md`、`.task/TASK-RC9-003.json` 和 `evidence/RC9-003-controlled-execution-binding-contract.json`，并更新 RC9 plan/session/state。合同定义 two-node target enrollment eligibility、exact approval packet fields、AgentCore PlanSpec binding、SecurityExecutionEngine effect envelope binding、controlled activation / rollback binding、TUI/frontend non-authority boundary 和 fail-closed cases；本 task 未 enroll real nodes、未授予 approval、未生成 executable PlanSpec、未执行 SecurityExecution effects、未安装、未激活、未回滚、未改 boot / active slot / persistent state / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。下一步是 `RC9-010` project immutable external object publication candidate for the RC8 payload bytes。
- `RC9-010` 已完成：新增 `scripts/project-rc9-external-object-publication.ps1`、`.workflow/artifacts/rc9-external-object-publication/result.json`、`external-object-publication-candidate.json`、`external-object-publication-denial.json`、`installer-handoff.json`、`.task/TASK-RC9-010.json` 和 `evidence/RC9-010-external-object-publication.json`，并更新 RC9 plan/session/state。脚本绑定 RC8 payload descriptor、当前 payload bytes、public signature receipt、RC8 mirror metadata 和 RC9 publication/drift contract；结果为 `passed`，但 publication state 是预期的 `publication-denied`，因为缺少 immutable external HTTPS object URI 且 declared/current artifact drift 仍未 reconciliation。未上传 payload、未远程下载 payload、未改 mirror metadata、未签名、未安装、未激活、未回滚、未改 boot / active slot / persistent state / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。下一步是 `RC9-011` reconcile declared and current artifact drift before external object trust。
- `RC9-011` 已完成：新增 `scripts/project-rc9-artifact-drift-reconciliation.ps1`、`.workflow/artifacts/rc9-artifact-drift-reconciliation/result.json`、`artifact-drift-reconciliation.json`、`drift-denial.json`、`installer-handoff.json`、`.task/TASK-RC9-011.json` 和 `evidence/RC9-011-artifact-drift-reconciliation.json`，并更新 RC9 plan/session/state。脚本对 current descriptor / payload / signature / mirror bindings 与 RC6/RC7 declared metadata 做 30 项比较，结果为 `passed`，reconciliation state 是预期的 `drift-denied`，识别 13 个 drift ids，包括 RC6 release id、RC7 signed/compat/rollback release id、RC7 required metadata digest 和 RC6 `update_metadata` / `release_channel_metadata` / `qemu_runtime_smoke` component hash drift。未修复或重写 declared metadata、未上传 payload、未下载 payload、未改 mirror metadata、未签名、未安装、未激活、未回滚、未改 boot / active slot / persistent state / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。下一步是 `RC9-012` run external object quarantine fetch and fail-closed installer evidence。
- `RC9-012` 已完成：新增 `scripts/project-rc9-external-object-installer-fetch.ps1`、`.workflow/artifacts/rc9-external-object-installer-fetch/result.json`、`external-object-fetch-report.json`、`installer-fail-closed-evidence.json`、`installer-gate-report.json`、`.task/TASK-RC9-012.json` 和 `evidence/RC9-012-external-object-installer-fetch.json`，并更新 RC9 plan/session/state。脚本消费 RC9-010 publication denial 和 RC9-011 drift denial，结果为 `passed`，fetch state 是预期的 `fetch-denied-before-network`，9 个 installer negative cases 全部 fail closed；未发起 network fetch、未下载 payload、未写 quarantine payload、未解释 payload、未签名、未安装、未激活、未回滚、未改 boot / active slot / persistent state / active artifact set / production ring，不开放 support upload / remote dispatch / TUI authority。下一步是 `RC9-020` enroll or deny two-node canary target set with compatibility and rollback bindings。
- `RC9-020` 已完成：新增 `scripts/project-rc9-two-node-canary-enrollment.ps1`、`.workflow/artifacts/rc9-two-node-canary-enrollment/result.json`、`canary-target-set.json`、`target-enrollment-denial.json`、`controlled-execution-handoff.json`、`.task/TASK-RC9-020.json` 和 `evidence/RC9-020-two-node-canary-enrollment.json`，并更新 RC9 plan/session/state。脚本消费 RC9-010 publication denial、RC9-011 drift denial、RC9-012 fetch denial、RC8 canary target set 和 RC8 rollback drill evidence，结果为 `passed`，target set state 是预期的 `target-set-enrollment-denied`：observed candidate node count 为 1，enrolled target count 为 0，required minimum target count 为 2；compatibility、rollback baseline 和 support/recovery bindings 已携带到 handoff，但不授权 activation、rollback、support upload 或 remote dispatch。下一步是 `RC9-021` bind exact operator approval to AgentCore PlanSpec and SecurityExecutionEngine approval。
- `RC9-021` 已完成：新增 `scripts/project-rc9-exact-approval-execution-binding.ps1`、`.workflow/artifacts/rc9-exact-approval-execution-binding/result.json`、`exact-approval-binding.json`、`agentcore-planspec-binding.json`、`security-execution-decision.json`、`execution-binding-denial.json`、`.task/TASK-RC9-021.json` 和 `evidence/RC9-021-exact-approval-execution-binding.json`，并更新 RC9 plan/session/state。脚本消费 RC9-020 target enrollment denial 和上游 publication / drift / fetch denial，结果为 `passed`，binding state 是预期的 `execution-binding-denied`：exact approval 未授予，AgentCore PlanSpec 仅有 deterministic core hash 且不可执行，SecurityExecutionEngine decision 拒绝 `controlled-canary-activation` effect；未准备或执行 install、activation、rollback、boot / active slot / active artifact set / production ring mutation、support upload 或 remote dispatch。下一步是 `RC9-022` execute or deny controlled canary activation through AgentCore and SecurityExecutionEngine gates。
- `RC9-022` 已完成：新增 `scripts/project-rc9-controlled-canary-activation.ps1`、`.workflow/artifacts/rc9-controlled-canary-activation/result.json`、`activation-gate-report.json`、`activation-denial-evidence.json`、`controlled-activation-handoff.json`、`.task/TASK-RC9-022.json` 和 `evidence/RC9-022-controlled-canary-activation.json`，并更新 RC9 plan/session/state。脚本消费 RC9-010 publication denial、RC9-011 drift denial、RC9-012 fetch denial、RC9-020 target enrollment denial 和 RC9-021 execution binding denial，结果为 `passed`，activation state 是预期的 `activation-denied`：activation_allowed=false、activation_performed=false、rollback_execution_allowed=false、remote_dispatch_enabled=false，并覆盖 10 个 fail-closed blockers。未准备或执行 install、activation、rollback、boot / active slot / persistent state / active artifact set / production ring mutation、support upload 或 remote dispatch。下一步是 `RC9-030` execute or deny rollback drill after controlled canary activation evidence。
- `RC9-030` 已完成：新增 `scripts/project-rc9-controlled-rollback-drill.ps1`、`.workflow/artifacts/rc9-controlled-rollback-drill/result.json`、`rollback-planspec-requirement.json`、`rollback-drill-gate-report.json`、`rollback-drill-denial-evidence.json`、`controlled-rollback-handoff.json`、`.task/TASK-RC9-030.json` 和 `evidence/RC9-030-controlled-rollback-drill.json`，并更新 RC9 plan/session/state。脚本消费 RC9-022 activation denial 和 handoff，结果为 `passed`，rollback state 是预期的 `rollback-denied`：rollback_execution_allowed=false、rollback_execution_performed=false、canary_activation_performed=false、support_upload_allowed=false、remote_dispatch_enabled=false，并覆盖 15 个 fail-closed blockers。未准备或执行 install、activation、rollback、boot / active slot / persistent state / active artifact set / production ring mutation、support upload 或 remote dispatch。下一步是 `RC9-031` bind support and recovery evidence to controlled canary and rollback outcomes。
- `RC9-031` 已完成：新增 `scripts/project-rc9-controlled-execution-support-recovery.ps1`、`.workflow/artifacts/rc9-controlled-execution-support-recovery/result.json`、`support-recovery-evidence-chain.json`、`controlled-execution-support-bundle.json`、`recovery-reference-index.json`、`.task/TASK-RC9-031.json` 和 `evidence/RC9-031-controlled-execution-support-recovery.json`，并更新 RC9 plan/session/state。脚本消费 RC9-022 activation denial、RC9-030 rollback denial / handoff、RC5 support/recovery metadata 和 RC7 rollback baseline，结果为 `passed`，support/recovery 已 hash-bound 但保持 `support_upload_allowed=false`、`recovery_execution_allowed=false`、`activation_performed=false`、`rollback_execution_performed=false`、`remote_dispatch_enabled=false`。未准备或执行 install、activation、rollback、recovery、boot / active slot / persistent state / active artifact set / production ring mutation、support upload 或 remote dispatch。下一步是 `RC9-040` Production Distro RC9 final audit and next milestone planning。
- `RC9-040` 已完成：新增 `scripts/run-rc9-final-closeout-audit.ps1`、`.workflow/artifacts/rc9-final-closeout-audit/result.json`、`evidence/FINAL-AUDIT-20260608-production-distro-rc9.json`、`docs/final-rc9-closeout-summary.md`、`.task/TASK-RC9-040.json` 和 `evidence/RC9-040-final-closeout-audit.json`，并将 RC9 plan/session 标记为 completed、state 推进到 RC10 planning。审计结论为 `PASS`，16 checks、0 blockers；RC9 仍不宣称 GA，且 external object publication、artifact drift、installer fetch、target enrollment、execution binding、activation、rollback、support/recovery 都按预期保持 fail-closed。下一步是 Production Distro RC10：real external object publication and controlled execution enablement。
- `RC10-001` 已完成：新增 `.workflow/active/WFS-20260608-agentos-production-distro-rc10/plan.json`、`workflow-session.json`、`docs/real-external-object-controlled-execution-enablement-contract.md`、`.task/TASK-RC10-001.json` 和 `evidence/RC10-001-real-external-object-controlled-execution-enablement-contract.json`，并将 state 切到 RC10 active。契约冻结 real immutable external object publication、drift-zero reconciliation、installer quarantine fetch verification、two-node canary enrollment、exact approval、AgentCore PlanSpec、SecurityExecutionEngine effect envelope、controlled activation、controlled rollback 和 support/recovery binding；本 task 未上传 payload、未签名、未安装、未激活、未回滚、未 mutation active slot / boot metadata / production ring，也未启用 remote dispatch。下一步是 `RC10-002` drift-zero external object descriptor publication contract。
- `RC10-002` 已完成：新增 `docs/drift-zero-external-object-publication-contract.md`、`.task/TASK-RC10-002.json` 和 `evidence/RC10-002-drift-zero-external-object-publication-contract.json`，并更新 RC10 plan/session/state。契约要求 external object descriptor publication 只有在 declared/current reconciliation 的 `drift_count=0` 时才能进入 `published-drift-zero`，并定义 canonical descriptor hashing、publication inputs、25 项 reconciliation comparisons、allowed states、installer handoff 和 denial evidence；仍保持 `production_ready_claim=false`、`install_allowed=false`、`activation_allowed=false`、`rollback_execution_allowed=false`，且未上传 payload、未签名、未下载远端 payload、未安装、未激活、未回滚、未启用 remote dispatch。下一步是 `RC10-003` exact approval canary activation and rollback execution contract。
- `RC10-003` 已完成：新增 `docs/exact-approval-canary-rollback-execution-contract.md`、`.task/TASK-RC10-003.json` 和 `evidence/RC10-003-exact-approval-canary-rollback-execution-contract.json`，并更新 RC10 plan/session/state。契约定义 controlled canary activation 和 controlled rollback 的 pre-execution chain、two-node target enrollment、exact approval packet、AgentCore activation/rollback PlanSpec、SecurityExecutionEngine activation/rollback effect envelope、allowed activation/rollback outcomes 和 fail-closed cases；Wave 0 contracts 已完成。当前仍未 enroll target、未 grant approval、未 bind executable PlanSpec、未执行 SecurityExecution effect、未安装、未激活、未回滚、未 mutation production ring，也未启用 remote dispatch。下一步是 `RC10-010` external object publication。
- `RC10-010` 已完成：新增 `scripts/project-rc10-external-object-publication.ps1`、`.workflow/artifacts/rc10-external-object-publication/result.json`、`publication-report.json`、`external-object-descriptor-candidate.json`、`publication-denial.json`、`installer-handoff.json`、`.task/TASK-RC10-010.json` 和 `evidence/RC10-010-external-object-publication.json`，并更新 RC10 plan/session/state。脚本结果为 `passed`，publication state 为 `publication-blocked-drift-nonzero`，8 checks、0 failed checks、2 个 publication blockers：`missing-external-https-object-uri` 和 `nonzero-declared-current-drift-count`；`drift_count=13`，所以未发布 external object URL。未上传 payload、未下载远端 payload、未签名、未安装、未激活、未回滚、未 mutation production ring，也未启用 remote dispatch。下一步是 `RC10-011` artifact drift-zero reconciliation。
- `RC10-011` 已完成：新增 `scripts/project-rc10-artifact-drift-zero-reconciliation.ps1`、`.workflow/artifacts/rc10-artifact-drift-zero-reconciliation/result.json`、`artifact-drift-zero-reconciliation.json`、`drift-zero-denial.json`、`installer-handoff.json`、`.task/TASK-RC10-011.json` 和 `evidence/RC10-011-artifact-drift-zero-reconciliation.json`，并更新 RC10 plan/session/state。脚本结果为 `passed`，reconciliation state 为 `drift-zero-denied`，6 checks、0 failed checks；它消费 RC10-010 publication evidence 和 RC9 30 项 drift comparisons，确认 `drift_count=13`，所以 external object trust 和 installer quarantine fetch 仍被阻断。未 repair drift、未 rewrite declared metadata、未上传 payload、未下载远端 payload、未安装、未激活、未回滚、未 mutation production ring，也未启用 remote dispatch。下一步是 `RC10-012` installer quarantine fetch。
- `RC10-012` 已完成：新增 `scripts/project-rc10-installer-quarantine-fetch.ps1`、`.workflow/artifacts/rc10-installer-quarantine-fetch/result.json`、`external-object-fetch-report.json`、`installer-fail-closed-evidence.json`、`installer-gate-report.json`、`.task/TASK-RC10-012.json` 和 `evidence/RC10-012-installer-quarantine-fetch.json`，并更新 RC10 plan/session/state。脚本结果为 `passed`，fetch state 为 `fetch-denied-before-network`，6 checks、0 failed checks、9 个 fail-closed cases 全部通过；它消费 RC10-010 publication evidence 和 RC10-011 drift-zero evidence，确认 `published_drift_zero=false`、`drift_zero_reconciled=false`，所以未尝试 network fetch、未写 quarantine payload、未解释 payload、未安装、未激活、未回滚、未 mutation production ring，也未启用 remote dispatch。Wave 1 已完成，下一步是 `RC10-020` two-node canary enrollment。
- `RC10-020` 已完成：新增 `scripts/project-rc10-two-node-canary-enrollment.ps1`、`.workflow/artifacts/rc10-two-node-canary-enrollment/result.json`、`canary-target-set.json`、`target-enrollment-denial.json`、`controlled-execution-handoff.json`、`.task/TASK-RC10-020.json` 和 `evidence/RC10-020-two-node-canary-enrollment.json`，并更新 RC10 plan/session/state。脚本结果为 `passed`，target set state 为 `target-set-enrollment-denied`，8 checks、0 failed checks；当前 observed candidate node count 为 1、enrolled target count 为 0、required minimum target count 为 2，并且 RC10 publication / drift-zero / installer quarantine fetch 仍未满足执行 gate。未伪造 target enrollment、未上传 payload、未 network fetch、未安装、未激活、未回滚、未 mutation production ring，也未启用 remote dispatch。下一步是 `RC10-021` exact approval execution binding。
- `RC10-021` 已完成：新增 `scripts/project-rc10-exact-approval-execution-enable.ps1`、`.workflow/artifacts/rc10-exact-approval-execution-enable/result.json`、`exact-approval-binding.json`、`agentcore-planspec-binding.json`、`security-execution-decision.json`、`execution-binding-denial.json`、`.task/TASK-RC10-021.json` 和 `evidence/RC10-021-exact-approval-execution-enable.json`，并更新 RC10 plan/session/state。脚本结果为 `passed`，binding state 为 `execution-binding-denied`，7 checks、0 failed checks；exact approval 未 granted，AgentCore PlanSpec 保持 non-executable，SecurityExecutionEngine 拒绝 controlled-canary-activation effect，并保留 11 个 fail-closed blockers。未伪造 approval、未执行 activation、未执行 rollback、未 support upload、未 mutation active slot / production ring，也未启用 remote dispatch。下一步是 `RC10-022` controlled canary activation。
- `RC10-022` 已完成：新增 `scripts/project-rc10-controlled-canary-activation.ps1`、`.workflow/artifacts/rc10-controlled-canary-activation/result.json`、`activation-gate-report.json`、`activation-denial-evidence.json`、`controlled-activation-handoff.json`、`.task/TASK-RC10-022.json` 和 `evidence/RC10-022-controlled-canary-activation.json`，并更新 RC10 plan/session/state。脚本结果为 `passed`，activation state 为 `activation-denied`，10 checks、0 failed checks、11 个 fail-closed denial cases 全部通过；它消费 RC10-010 publication denial、RC10-011 drift-zero denial、RC10-012 fetch denial、RC10-020 target enrollment denial 和 RC10-021 execution binding denial。未执行 activation、未执行 rollback、未 support upload、未 mutation active slot / boot metadata / production ring，也未启用 remote dispatch。下一步是 `RC10-030` controlled rollback drill。
- `RC10-030` 已完成：新增 `scripts/project-rc10-controlled-rollback-drill.ps1`、`.workflow/artifacts/rc10-controlled-rollback-drill/result.json`、`rollback-planspec-requirement.json`、`rollback-drill-gate-report.json`、`rollback-drill-denial-evidence.json`、`controlled-rollback-handoff.json`、`.task/TASK-RC10-030.json` 和 `evidence/RC10-030-controlled-rollback-drill.json`，并更新 RC10 plan/session/state。脚本结果为 `passed`，rollback state 为 `rollback-denied`，9 checks、0 failed checks、19 个 rollback denial cases 全部通过；它消费 RC10-022 activation denial 和 handoff，并证明 activation 未执行、rollback approval 未 granted、rollback PlanSpec 未 executable、SecurityExecutionEngine rollback approval 未 bound。未执行 rollback、未 support upload、未 mutation active slot / boot metadata / production ring，也未启用 remote dispatch。下一步是 `RC10-031` controlled execution support/recovery。
- `RC10-031` 已完成：新增 `scripts/project-rc10-controlled-execution-support-recovery.ps1`、`.workflow/artifacts/rc10-controlled-execution-support-recovery/result.json`、`support-recovery-evidence-chain.json`、`controlled-execution-support-bundle.json`、`recovery-reference-index.json`、`.task/TASK-RC10-031.json` 和 `evidence/RC10-031-controlled-execution-support-recovery.json`，并更新 RC10 plan/session/state。脚本结果为 `passed`，10 checks、0 failed checks；它绑定 RC10-022 activation denial、RC10-030 rollback denial、rollback PlanSpec requirement、support metadata、recovery operations、compatibility metadata 和 rollback baseline。support bundle 仍是 redacted local projection，support upload / recovery execution / activation / rollback / remote dispatch 全部为 false，并保留 19 个 controlled execution blockers。下一步是 `RC10-040` final closeout audit。
- `RC10-040` 已完成：新增 `scripts/run-rc10-final-closeout-audit.ps1`、`.workflow/artifacts/rc10-final-closeout-audit/result.json`、`.workflow/active/WFS-20260608-agentos-production-distro-rc10/evidence/FINAL-AUDIT-20260608-production-distro-rc10.json`、`.workflow/active/WFS-20260608-agentos-production-distro-rc10/docs/final-rc10-closeout-summary.md`、`.task/TASK-RC10-040.json` 和 `evidence/RC10-040-final-closeout-audit.json`，并更新 RC10 plan/session/state。审计结果为 `passed`，16 checks、0 blockers；RC10 关闭为 non-GA fail-closed milestone，仍未执行 install / activation / rollback / recovery / support upload / production ring mutation / remote dispatch。RC11 planning 已完成，下一步是 `RC11-001` real-object trust handoff contract。
- `RC11-000` 和 `RC11-001` 已完成：新增 `.workflow/active/WFS-20260609-agentos-production-distro-rc11/plan.json`、`workflow-session.json`、`.task/TASK-RC11-*.json`、`docs/rc11-real-object-controlled-execution-unblock-plan.md`、`docs/real-object-trust-handoff-contract.md`、`evidence/RC11-000-planning.json` 和 `evidence/RC11-001-real-object-trust-handoff-contract.json`，并把 state / TASK 指针推进到 `RC11-010`。RC11 明确只做 AIOS 本体：外部 object reachability 不是 trust，后续必须通过 descriptor classification、drift-zero、quarantine fetch、signature/revocation、compatibility、rollback baseline、support/recovery、AgentCore PlanSpec 和 SecurityExecutionEngine gates，仍不做 mirror frontend、Nginx、远端 signer、install、activation、rollback、support upload、production ring mutation 或 remote dispatch。
- `RC3-030` 已完成：Production Distro RC3 final audit and next milestone planning 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/FINAL-AUDIT-20260531-production-distro-rc3.json` 和 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/docs/final-rc3-closeout-summary.md`。审计结论为 `PASS`，覆盖 `RC3-001` 到 `RC3-023` 共 12 个 pre-closeout task；production signature verification 通过 41 个 required artifacts，其中 9 个为 RC2 true block-device artifacts；release publication、signed channel consumer、support/recovery projection 和 signing/publication gate 均通过且 blockers 为 0；RC3 仍不宣称 GA。
- `RC4-001` 到 `RC4-004` 已完成：hosted release transport / remote registry mirror / fleet-ring boundary、staged rollout authority / rollback boundary、GA hardening acceptance gates 和 hosted transport / fleet rollout threat model 已冻结。关键证据位于 `.workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/RC4-001-hosted-release-transport-fleet-contract.json` 到 `.workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/RC4-004-hosted-transport-fleet-threat-model.json`。
- `RC4-010` 已完成：新增 `scripts/publish-rc4-hosted-release-transport.ps1`，生成 `.workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json` 和 `.workflow/artifacts/rc4-hosted-release-transport/local-mirror-fixture.json`，结果 `.workflow/artifacts/rc4-hosted-release-transport/result.json` 为 `passed`、15 checks、0 blockers。manifest 绑定 RC3 final audit、production verification、publication manifest、channel index、consumer smoke、support/recovery、signing/publication gate 和 revocation log hashes；local mirror fixture 绑定实际 hosted manifest 文件 sha256；不联网、不上传、不签名、不激活、不执行 rollback、不改 active slot / active registry / production ring，`production_ready_claim=false`。
- `RC4-011` 已完成：新增 `scripts/replay-rc4-remote-registry-mirror-publication.ps1`，生成 `.workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-lockfile.json` 和 `.workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-publication.json`，结果 `.workflow/artifacts/rc4-remote-registry-mirror-publication/result.json` 为 `passed`、12 checks、0 blockers、8 个 mirror entries、0 hash mismatches。replay 只使用本地 fixture，不联网、不上传、不签名、不激活、不执行 rollback、不改 active registry / active slot / production ring，`production_ready_claim=false`。
- `RC4-012` 已完成：新增并加强 `scripts/audit-rc4-fleet-ring-rollout-preconditions.ps1`，生成 `.workflow/artifacts/rc4-fleet-ring-rollout-preconditions/result.json`，结果为 `ready-for-fleet-ring-rollout-plan`、18 checks、0 blockers。审计绑定 hosted transport、mirror publication、fleet rollout authority、rollback baseline、support/recovery、target set hash、rollout policy version 和 revocation snapshot，并检查 mirror freshness、fail-closed case 声明和 ring 顺序；它只证明可以进入 fleet-ring rollout plan 阶段，不生成 rollout plan、不授予 operator approval、不执行 activation / rollback、不改 active registry / active slot / production ring，`production_ready_claim=false`。
- `RC4-013` 已完成：新增 `scripts/verify-rc4-hosted-transport-fail-closed-fixtures.ps1`，生成 `.workflow/artifacts/rc4-hosted-transport-fail-closed-fixtures/result.json`，结果为 `passed`、13 个 negative cases 全部通过、0 blockers。覆盖 hosted manifest hash drift、missing RC3 final audit binding、stale mirror snapshot、unsigned/revoked mirror metadata、registry lockfile mismatch、fleet target set drift、ring skip、missing rollback baseline、TUI/model/remote authority attempt 和 unredacted support bundle；每个 case 都让 RC4-012 audit fail closed，且不生成 rollout plan、不授予 approval、不执行 activation / rollback、不改 active registry / active slot / production ring。
- `RC4-020` 已完成：新增 `scripts/run-rc4-signed-hosted-channel-consumer-mirror-smoke.ps1`，生成 `.workflow/artifacts/rc4-signed-hosted-channel-consumer-mirror-smoke/result.json`，结果为 `passed`、11 checks、0 blockers。smoke 验证 hosted transport manifest、local mirror fixture、mirror lockfile/publication、RC4 preconditions、RC4 fail-closed fixtures、RC3 signed channel consumer、RC3 publication/channel metadata、production signature verification 和 revocation snapshot 的 hash 绑定一致；不联网、不上传、不签名、不激活、不执行 rollback、不改 active registry / active slot / production ring，`production_ready_claim=false`。
- `RC4-021` 已完成：新增 `scripts/run-rc4-staged-fleet-ring-rollout-smoke-rollback-drill.ps1`，生成 `.workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/result.json`、`staged-rollout-plan-projection.json` 和 `rollback-drill-projection.json`，结果为 `passed`、12 checks、0 blockers。smoke 验证 RC4-020 hosted consumer / mirror smoke、RC4-012 rollout preconditions、RC4-013 fail-closed fixtures、fleet rollout authority、local ring readiness、exact operator approval gate、RC2 rollback baseline 和 RC3 support/recovery redaction；只创建本地 projection，不创建可执行 rollout plan、不授予 approval、不执行 activation / rollback、不改 active registry / active slot / production ring，`production_ready_claim=false`。
- `RC4-022` 已完成：新增 `scripts/project-rc4-ga-hardening-support-recovery.ps1`，生成 `.workflow/artifacts/rc4-ga-hardening-support-recovery-projection/result.json`、`hosted-fleet-support-bundle-redacted.json`、`hosted-fleet-recovery-projection.json` 和 `support-recovery-index.json`，结果为 `passed`、16 checks、0 blockers。projection 解释 hosted transport、mirror、fleet rollout、rollback baseline、RC3 support/recovery、support upload 和 incident runbook 状态，并证明 support bundle redacted、local-only、无 remote upload / activation / rollback execution / active slot mutation / production ring mutation / TUI authority，`production_ready_claim=false`。
- `RC4-023` 已完成：新增 `scripts/integrate-rc4-hosted-fleet-promotion-gates.ps1`，生成 `.workflow/artifacts/rc4-hosted-fleet-promotion-gate-integration/result.json` 和 `.workflow/artifacts/release/rc4-hosted-fleet-promotion-gate.json`，结果为 `passed`、16 checks、0 blockers。promotion gate 绑定 hosted transport、mirror、fleet preconditions、hosted fail-closed fixtures、hosted consumer/mirror smoke、staged fleet rollout smoke、GA support/recovery、fleet rollout authority、candidate promotion baseline、release provenance baseline 和 RC3 signing/publication gate；不改 release provenance / candidate promotion、不执行 activation / rollback、不改 active registry / active slot / production ring、不开放 remote dispatch / TUI authority，`production_ready_claim=false`。
- `RC4-030` 已完成：新增 `scripts/run-rc4-final-closeout-audit.ps1`，生成 `.workflow/artifacts/rc4-final-closeout-audit/result.json`、`.workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/FINAL-AUDIT-20260608-production-distro-rc4.json` 和 `.workflow/active/WFS-20260608-agentos-production-distro-rc4/docs/final-rc4-closeout-summary.md`。审计结论为 `PASS`，21 checks、0 blockers，覆盖 hosted transport、remote registry mirror、fleet rollout、rollback projection、support/recovery 和 promotion gate；RC4 仍不宣称 GA，下一 milestone 规划为 Production Distro RC5：controlled hosted transport service and multi-node fleet canary execution proof。
- `RC0-001` 已完成：production signing public trust store 已进入 rootfs package defaults，`scripts/validate-alpha-rootfs.ps1` 会校验 public key custody / rotation / revocation metadata、拒绝 private material，并且 `scripts/build-release.ps1` 会把这些 trust store hashes 纳入 release provenance 与 runtime artifact gate；`scripts/create-production-signing-request.ps1` 和 `scripts/verify-production-signatures.ps1` 默认绑定 packaged rootfs trust store。本轮 full `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120` 通过，`promotion.status=promotable` 且 blockers 为空；`scripts/replay-production-signing-material-intake.ps1 -UseLocalReleaseAuthority -RequireDecisionEvidence -AllowSignatureOverwrite -SkipQemuSmoke -FailOnBlocked` 通过，生成 public signature bundle、安装 13 个 `.prod.sig.json`，并完成 packaged keyring cryptographic verification、production signature verification 和 production promotion verification，bundle 未包含 private/secret-like 字段或 private PEM。
- `RC0-002` 已完成：`scripts/build-release.ps1` 生成独立 `release-channel-metadata.json`，绑定 immutable / append-only / content-addressed RC0 channel policy、inactive-slot update strategy、no in-place active slot mutation、ecosystem replay rollback drill evidence、previous/restored active artifact set hash 和 release promotion gate；candidate detached signatures、production signing request、production signature verification、candidate promotion verification、release reproducibility 和 TUI release/signing projections 均纳入 `release_channel_metadata`。本轮 full `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120` 通过，`promotion.status=promotable` 且 blockers 为空；`scripts/verify-release-reproducibility.ps1 -ArtifactRoot .workflow/artifacts/release-reproducibility-fast -OutputPath .workflow/artifacts/release-reproducibility-fast/result.json` 通过，`matched=34`、`divergent=0`；`scripts/replay-production-signing-material-intake.ps1 -UseLocalReleaseAuthority -RequireDecisionEvidence -AllowSignatureOverwrite -SkipQemuSmoke -FailOnBlocked` 通过，production signing request / verification required artifacts 增至 14 个且 blockers 为 0；`scripts/verify-candidate-promotion.ps1 -OutputPath .workflow/artifacts/candidate-promotion/default-result.json -FailOnBlocked` 通过。
- `RC0-003` 已完成：fleet rollout authority 已从 TUI projection panels 拆出为 release artifact。`scripts/build-release.ps1` 生成 `fleet-rollout-authority.json` 和 detached candidate signature，并把 `fleet_rollout_authority` 纳入 provenance、required detached signatures、candidate promotion verification、release reproducibility、production signing request / verification 和 TUI rollout projection；artifact 明确 `execution_authority=AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine`，且 `tui_authority=false`、`rollout_execution_in_tui=false`、`rollout_mutation_in_tui=false`、`remote_command_dispatch_in_tui=false`、`rollback_execution_in_tui=false`、`promotion_authority_in_tui=false`。本轮 `scripts/verify-release-reproducibility.ps1 -ArtifactRoot .workflow/artifacts/release-reproducibility-fast -OutputPath .workflow/artifacts/release-reproducibility-fast/result.json` 通过，`matched=38`、`divergent=0`；full `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120` 通过，`promotion.status=promotable` 且 blockers 为空；`scripts/verify-candidate-promotion.ps1 -OutputPath .workflow/artifacts/candidate-promotion/default-result.json -FailOnBlocked` 通过，287 个检查通过、fleet authority 相关失败数为 0；`scripts/replay-production-signing-material-intake.ps1 -UseLocalReleaseAuthority -RequireDecisionEvidence -AllowSignatureOverwrite -SkipQemuSmoke -FailOnBlocked` 通过，production signing request / verification required artifacts 增至 15 个且包含 `fleet_rollout_authority`。
- `RC0-004` 已完成：support bundle upload 现在通过 `support.bundle.upload` semantic tool、destination trust hash、exact operator consent 和 redaction policy gate 进入 AgentCore / SecurityExecutionEngine 路径；TUI 只发起 preview / consent projection，实际 upload 语义为 local spool evidence，明确 `remote_bytes_sent=false`、`transport=local-spool`、`upload_spooled=true`。`scripts/support-bundle-upload-replay.ps1` 通过，证据 schema 为 `agentos.support-bundle-upload-replay.v1`，并证明 `local_only=true`、`real_network_transfer_enabled=false`、`destination_trust_required=true`、`exact_operator_consent_required=true`、`execution_authority=AgentCore PlanSpec + SecurityExecutionEngine`、`tui_authority=false`；full `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120` 通过，release provenance 包含 `support_bundle_upload_replay` 且 `promotion.status=promotable`、blockers 为 0；`scripts/verify-release-reproducibility.ps1 -ArtifactRoot .workflow/artifacts/release-reproducibility-fast -OutputPath .workflow/artifacts/release-reproducibility-fast/result.json` 通过，`matched=40`、`divergent=0`；`scripts/replay-production-signing-material-intake.ps1 -UseLocalReleaseAuthority -RequireDecisionEvidence -AllowSignatureOverwrite -SkipQemuSmoke -FailOnBlocked` 通过，production signing request / verification required artifacts 增至 16 个且包含 `support_bundle_upload_replay`。
- `RC0-005` 已完成：remote registry mirror refresh 现在有 release decision evidence artifact `remote_registry_mirror_replay`。`scripts/remote-registry-mirror-replay.ps1` 只使用 local fixture mirror，不需要真实网络，生成 quarantined candidate registry snapshot、mirror trust record、detached signature fixture、rollback previous snapshot evidence，并运行 `cargo test -p agent_core registry_refresh`、`cargo test -p security_execution registry_refresh` 和 candidate `aom verify`；证据证明 `local_registry_authoritative=true`、`remote_registry_authority=false`、`real_network_transfer_enabled=false`、`active_registry_mutated=false`、`local_snapshot_replaced=false`、`candidate_quarantined=true`、`exact_operator_consent_required=true`、`rollback_required=true`、`execution_authority=AgentCore registry_refresh PlanSpec + SecurityExecutionEngine`、`tui_authority=false`。本轮 full `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120` 通过，release provenance 包含 `remote_registry_mirror_replay` 且 `promotion.status=promotable`、blockers 为 0；`scripts/verify-release-reproducibility.ps1 -ArtifactRoot .workflow/artifacts/release-reproducibility-fast -OutputPath .workflow/artifacts/release-reproducibility-fast/result.json` 通过，`matched=42`、`divergent=0`；`scripts/verify-candidate-promotion.ps1 -OutputPath .workflow/artifacts/candidate-promotion/default-result.json -FailOnBlocked` 通过，375 个检查通过、blockers 为 0；`scripts/replay-production-signing-material-intake.ps1 -UseLocalReleaseAuthority -RequireDecisionEvidence -AllowSignatureOverwrite -SkipQemuSmoke -FailOnBlocked` 通过，production signing request / verification required artifacts 增至 17 个且包含 `remote_registry_mirror_replay`。同时对 invalid signature、untrusted mirror、malformed response、expired local snapshot 执行 fail-closed 证据检查，并增加 `no-secret-echo` 证据。
- `RC0-006` 已完成：organization policy overlay activation 现在通过 AgentCore `organization_overlay` PlanSpec 和 SecurityExecutionEngine 执行路径建模，新增 `org.overlay.signature.verify`、`org.overlay.diff.evaluate`、`org.overlay.replay.verify` 和 `org.overlay.activate` semantic tools；TUI 只保留 preview/projection，不拥有 overlay activation authority。`scripts/organization-policy-overlay-replay.ps1` 只使用 local staged fixture，生成 overlay、detached signature、diff 和 rollback baseline policy evidence，证据 schema 为 `agentos.organization-policy-overlay-replay.v1`，并证明 `local_policy_authoritative=true`、`remote_policy_authority=false`、`real_network_transfer_enabled=false`、`active_policy_mutated=false`、`staged_inert=true`、`signature_required=true`、`revocation_check_required=true`、`policy_diff_required=true`、`replay_required=true`、`exact_operator_consent_required=true`、`rollback_required=true`、`authority_broadening_allowed=false`、`execution_authority=AgentCore organization_overlay PlanSpec + SecurityExecutionEngine`、`tui_authority=false`。本轮 `cargo test -p agent_core organization_overlay -- --nocapture` 通过 5 个测试，`cargo test -p security_execution organization_overlay -- --nocapture` 通过 2 个测试，`scripts/validate-alpha-rootfs.ps1` 通过，`scripts/organization-policy-overlay-replay.ps1` 通过；full `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120` 通过，release provenance 包含 `organization_policy_overlay_replay` 且 `promotion.status=promotable`、blockers 为 0；`scripts/verify-release-reproducibility.ps1 -ArtifactRoot .workflow/artifacts/release-reproducibility-fast -OutputPath .workflow/artifacts/release-reproducibility-fast/result.json` 通过，`matched=44`、`divergent=0`；`scripts/verify-candidate-promotion.ps1 -OutputPath .workflow/artifacts/candidate-promotion/default-result.json -FailOnBlocked` 通过，450 个检查通过、blockers 为 0；`scripts/replay-production-signing-material-intake.ps1 -UseLocalReleaseAuthority -RequireDecisionEvidence -AllowSignatureOverwrite -SkipQemuSmoke -FailOnBlocked` 通过，production signing request / verification required artifacts 增至 18 个且包含 `organization_policy_overlay_replay`。同时对 unsigned overlay、revoked overlay、invariant weakening、authority broadening 和 missing rollback 执行 fail-closed 证据检查，并增加 `no-secret-echo` 证据。
- `RC0-007` 已完成：node enrollment、local identity and fleet audit evidence model 已通过 AgentCore `node_enrollment` PlanSpec 和 SecurityExecutionEngine 执行路径建模，新增 `node.identity.project`、`node.enrollment.attest`、`fleet.audit.verify` 和 `node.enrollment.activate` semantic tools；TUI 只保留 projection，不拥有 node enrollment activation authority。`scripts/node-enrollment-fleet-audit-replay.ps1` 只使用 local evidence，不需要真实网络，证据 schema 为 `agentos.node-enrollment-fleet-audit-replay.v1`，并证明 `local_identity_authoritative=true`、`remote_control_plane_authority=false`、`remote_command_dispatch_enabled=false`、`active_enrollment_mutated=false`、`raw_enrollment_token_present=false`、`enrollment_token_handle_only=true`、release provenance / active artifact set / audit seal 均已绑定、`exact_operator_consent_required=true`、`rollback_required=true`、`security_execution_required=true`、`tui_authority=false`。本轮 `cargo test -p agent_core node_enrollment -- --nocapture` 通过 5 个测试，`cargo test -p security_execution node_enrollment -- --nocapture` 通过 2 个测试，`scripts/validate-alpha-rootfs.ps1` 通过，`scripts/node-enrollment-fleet-audit-replay.ps1` 通过；full `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120` 通过，release provenance 包含 `node_enrollment_fleet_audit_replay` 且 `promotion.status=promotable`、blockers 为 0；`scripts/verify-release-reproducibility.ps1 -ArtifactRoot .workflow/artifacts/release-reproducibility-fast -OutputPath .workflow/artifacts/release-reproducibility-fast/result.json` 通过，`matched=46`、`divergent=0`；`scripts/verify-candidate-promotion.ps1 -OutputPath .workflow/artifacts/candidate-promotion/default-result.json -FailOnBlocked` 通过，517 个检查通过、blockers 为 0；`scripts/replay-production-signing-material-intake.ps1 -UseLocalReleaseAuthority -RequireDecisionEvidence -AllowSignatureOverwrite -SkipQemuSmoke -FailOnBlocked` 通过，production signing request / verification required artifacts 增至 19 个且包含 `node_enrollment_fleet_audit_replay`。同时对 raw enrollment token、missing audit seal、remote dispatch attempt、node identity mismatch、missing rollback 和 stale provenance 执行 fail-closed 证据检查，并增加 `no-secret-echo` 证据。
- `RC0-008` 已完成：long-running TUI session hardening、profile persistence and degraded offline UX 已落地。TUI 新增本地 session profile schema `agentos.tui-session-profile.v1`，支持 `session.profile.show`、`session.profile.save`、`session.profile.set <focus|selected_run|event_limit|degraded_ack> <value>` 和 CLI `--session-profile <path>`；profile 持久化只保存 local non-secret UI preference，拒绝 secret-like 值，明确 `remote_authority=false`、`projection_controller_only=true`、`profile_permission_authority=false`，不是 AgentCore / SecurityExecution permission authority。`scripts/tui-session-hardening-replay.ps1` 通过，证据 schema 为 `agentos.tui-session-hardening-replay.v1`，19 个检查全部通过、run snapshots 为 26，证明跨 controller reopen 能恢复 profile、RunStore 和 AuditJournal，offline/degraded explainer 可渲染，secret profile value 和 shell syntax fail closed，且 `real_network_transfer_enabled=false`、无 profile-created SecurityExecution effects、无 secret echo。为保证 release reproducibility，replay artifact 只输出稳定逻辑路径和已验证不变量 hash，不把本地 `first/second` artifact root 写入决策证据。`cargo test -p agentd tui_session_profile -- --nocapture` 通过 2 个测试，`cargo test -p agentd tui -- --nocapture` 通过 86 个 TUI 测试，`scripts/validate-alpha-rootfs.ps1` 通过；full `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120` 通过，release provenance 包含 `tui_session_hardening_replay` 且 `promotion.status=promotable`、blockers 为 0；`scripts/verify-candidate-promotion.ps1 -OutputPath .workflow/artifacts/candidate-promotion/default-result.json -FailOnBlocked` 通过，557 个检查通过、blockers 为 0；`scripts/verify-release-reproducibility.ps1 -ArtifactRoot .workflow/artifacts/release-reproducibility-fast -OutputPath .workflow/artifacts/release-reproducibility-fast/result.json` 通过，`matched=48`、`divergent=0`；`scripts/replay-production-signing-material-intake.ps1 -UseLocalReleaseAuthority -RequireDecisionEvidence -AllowSignatureOverwrite -SkipQemuSmoke -FailOnBlocked` 通过，production signing request required artifacts 为 20 个且包含 `tui_session_hardening_replay`。
- `RC0-009` 已完成：marketplace governance and artifact review workflow 已通过 AgentCore `marketplace_review` PlanSpec 和 SecurityExecutionEngine semantic tools 建模，新增 marketplace publisher verify、artifact review、policy evaluate 和 review publish 执行语义；TUI 仍是 projection-controller，不拥有 marketplace governance authority。`scripts/marketplace-governance-replay.ps1` 通过，证据 schema 为 `agentos.marketplace-governance-replay.v1`，覆盖 unsigned artifact、malicious manifest script、policy weakening、secret embedding、missing reviewer quorum、revoked publisher 和 review replay mismatch 7 个 fail-closed 场景，并证明 `local_only=true`、`network_required=false`、`real_network_transfer_enabled=false`、`marketplace_remote_authority=false`、review 前不 mutate registry / review queue、不 activate artifact，publish 需要 exact operator consent 和 rollback。`cargo test -p agent_core marketplace_review -- --nocapture` 通过 6 个测试，`cargo test -p security_execution marketplace_review -- --nocapture` 通过 2 个测试，`scripts/validate-alpha-rootfs.ps1` 通过；full `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120` 通过，release provenance 包含 `marketplace_governance_replay` 且 `promotion.status=promotable`、blockers 为 0；`scripts/verify-candidate-promotion.ps1 -OutputPath .workflow/artifacts/candidate-promotion/default-result.json -FailOnBlocked` 通过，631 个检查通过、blockers 为 0；`scripts/verify-release-reproducibility.ps1 -ArtifactRoot .workflow/artifacts/release-reproducibility-fast -OutputPath .workflow/artifacts/release-reproducibility-fast/result.json` 通过，`matched=50`、`divergent=0`；`scripts/replay-production-signing-material-intake.ps1 -UseLocalReleaseAuthority -RequireDecisionEvidence -AllowSignatureOverwrite -SkipQemuSmoke -FailOnBlocked` 通过，production signing request / verification required artifacts 增至 21 个且包含 `marketplace_governance_replay`。
- `RC0-010` 已完成：production incident runbooks with recovery and rollback drills 已通过 AgentCore `incident_runbook` PlanSpec 和 SecurityExecutionEngine semantic tools 建模，新增 incident state snapshot、recovery verify、rollback verify 和 runbook publish 执行语义；TUI 仍是 projection-controller，不拥有 incident recovery / rollback authority。`scripts/production-incident-runbook-replay.ps1` 通过，证据 schema 为 `agentos.production-incident-runbook-replay.v1`，覆盖 missing audit seal、model replay recovery、remote dispatch attempt、missing exact approval、rollback hash mismatch、unredacted support bundle 和 production ring mutation 7 个 fail-closed 场景，并证明 `local_only=true`、`network_required=false`、`real_network_transfer_enabled=false`、`remote_dispatch_enabled=false`、`remote_control_plane_authority=false`、recovery truth 来自 `RunStore + AuditJournal + release rollback evidence`、`no_model_replay=true`、publish 需要 exact operator consent 和 rollback、rollback 恢复 previous active artifact set hash、support bundle redacted、production ring / active slot / active artifact set 均不被 replay mutation。`cargo test -p agent_core incident_runbook -- --nocapture` 通过 5 个测试，`cargo test -p security_execution incident_runbook -- --nocapture` 通过 2 个测试，`scripts/validate-alpha-rootfs.ps1` 通过；full `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120` 通过，release provenance 包含 `production_incident_runbook_replay` 且 `promotion.status=promotable`、blockers 为 0，fleet rollout local proof 中 `production_incident_runbook_status=passed`；`scripts/verify-candidate-promotion.ps1 -OutputPath .workflow/artifacts/candidate-promotion/default-result.json -FailOnBlocked` 通过，686 个检查通过、blockers 为 0；`scripts/verify-release-reproducibility.ps1 -ArtifactRoot .workflow/artifacts/release-reproducibility-fast -OutputPath .workflow/artifacts/release-reproducibility-fast/result.json` 通过，`matched=52`、`divergent=0`；`scripts/replay-production-signing-material-intake.ps1 -UseLocalReleaseAuthority -RequireDecisionEvidence -AllowSignatureOverwrite -SkipQemuSmoke -FailOnBlocked` 通过，production signing request / verification required artifacts 增至 22 个且包含 `production_incident_runbook_replay`。
- `RC0-FINAL-001` 已完成：Production Distro RC0 closeout audit and next milestone planning 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc0/evidence/FINAL-AUDIT-20260530-production-distro-rc0.json` 和 `.workflow/active/WFS-20260530-agentos-production-distro-rc0/docs/final-rc0-closeout-summary.md`。审计结论为 `PASS`，覆盖 `RC0-001` 到 `RC0-010` 共 10 个 task；当前 `.workflow/artifacts/release/provenance.json` 为 `agentos.production-candidate.provenance.v1`，`promotion.status=promotable`、blockers 为空，QEMU runtime smoke 观察到全部 marker，fleet rollout authority 和 local proof 均为 passed；candidate promotion 通过 686 个检查且 blockers 为 0；release reproducibility 通过，`matched=52`、`divergent=0`；production signing material intake 通过，decision evidence required artifacts 为 22 个并包含 `production_incident_runbook_replay`。这仍不是 GA production-ready claim，下一步进入 Production Distro RC1：installable distro image and first-boot provisioning。
- `RC1-001` 已完成：installable distro image and first-boot provisioning contract 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/docs/installable-image-first-boot-contract.md`，task evidence 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-001-installable-image-first-boot-contract.json`。契约冻结 install media、installed system layout 和 first-boot provisioning 三段边界，明确 copy/stage 不是 activate，禁止 media 携带 private/secret material，禁止 normal shell bypass，first boot 必须本地初始化 identity handle、RunStore、AuditJournal、audit seal 和 rollback baseline，所有 activation side effects 仍归 AgentCore PlanSpec + SecurityExecutionEngine。
- `RC1-002` 已完成：installed disk layout、A/B slots、EFI/BIOS boot metadata and persistent state mount policy 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/docs/installed-disk-layout-and-state-policy.md`，task evidence 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-002-installed-disk-layout-policy.json`。契约把 RC0 的 `ab-rootfs`、inactive-slot staging、rollback required 和 no active-slot in-place mutation 约束落到 installed disk schema、boot slot metadata、rootfs slot A/B、state partition 和 persistent state mount policy。
- `RC1-003` 已完成：first-boot local identity、audit seal and recovery baseline schema 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/docs/first-boot-identity-audit-recovery-schema.md`，task evidence 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-003-first-boot-identity-audit-recovery-schema.json`。契约定义 `agentos.first-boot-provisioning.v1`、local identity projection、RunStore / AuditJournal genesis、first-boot audit seal 和 recovery baseline，禁止 raw secrets、raw enrollment token、network-required first boot、external LLM、model replay recovery、normal shell provisioning 和 TUI mutation authority。
- `RC1-004` 已完成：installer threat model 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/docs/installer-threat-model.md`，task evidence 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-004-installer-threat-model.json`。威胁模型覆盖 media tampering、missing / revoked signature、private material / raw secret in media、shell bypass、maintainer script / host fallback、active-slot mutation、slot metadata mismatch、state inside rootfs、first-boot network / external LLM requirement、model replay recovery 和 TUI mutation attempt，全部要求 fail closed before effects。
- `RC1-010` 已完成：installable image manifest and deterministic media metadata 已实现为 `scripts/create-installable-media-manifest.ps1`。脚本生成 `.workflow/artifacts/rc1-installable-media/installable-media-manifest.json`（schema `agentos.installable-media-manifest.v1`，media id `sha256:49a15a66f83e326c6fb0b3b6cc0ae822de880c1c20e93de9d934314d284e5456`）和 `.workflow/artifacts/rc1-installable-media/result.json`（schema `agentos.installable-media-manifest-result.v1`，status `passed`，36 checks passed、0 failed）。task evidence 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-010-installable-media-manifest.json`。
- `RC1-011` 已完成：local disk image assembly path with rootfs/runtime artifacts 已实现为 `scripts/assemble-installed-disk-image.ps1`。脚本生成 `.workflow/artifacts/rc1-installed-disk/installed-disk-layout.json`（schema `agentos.installed-disk-layout.v1`，disk id `sha256:c7d4f73d10b465548db803248f51919092e977202e7d96f242b057e6582e9db9`）和 `.workflow/artifacts/rc1-installed-disk/result.json`（schema `agentos.installed-disk-assembly-result.v1`，status `passed`，10 checks passed、0 failed）。task evidence 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-011-installed-disk-assembly.json`。
- `RC1-012` 已完成：first-boot provisioning replay with local identity and audit seal 已实现为 `scripts/first-boot-provisioning-replay.ps1`。脚本生成 `.workflow/artifacts/rc1-first-boot/result.json`（schema `agentos.first-boot-provisioning-replay.v1`，status `passed`，19 checks passed、13 fail-closed scenarios），并生成 local identity projection、RunStore / AuditJournal genesis、audit seal、rollback baseline 和 recovery baseline。task evidence 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-012-first-boot-provisioning-replay.json`。
- `RC1-013` 已完成：installer fail-closed fixtures 已实现为 `scripts/installer-fail-closed-fixtures.ps1`。脚本生成 `.workflow/artifacts/rc1-installer-fail-closed/result.json`（schema `agentos.installer-fail-closed-fixtures.v1`，status `passed`，25 checks passed、21 fail-closed scenarios），覆盖 corrupted media、missing / revoked signature、stale provenance、private material、raw secret、shell bypass、maintainer script / host fallback、slot mismatch、state inside rootfs、first-boot network / external LLM、model replay、missing genesis / rollback / audit seal 和 TUI mutation attempt。task evidence 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-013-installer-fail-closed-fixtures.json`。
- `RC1-020` 已完成：installed-system QEMU boot smoke with first-boot markers 已实现为 `scripts/installed-system-qemu-smoke.ps1`，并扩展 `image/build-initramfs.ps1` / `scripts/boot-smoke-test.ps1` 支持可选 additional marker manifest、独立 initramfs out/source 目录和 artifact-local smoke。脚本生成 `.workflow/artifacts/rc1-installed-system-smoke/result.json`（schema `agentos.installed-system-qemu-smoke.v1`，status `passed`，15 checks passed、0 failed），QEMU 在 `pc` machine 上观察到 22 个 required markers：handoff、runtime artifact、TUI console、runtime manifest、projection-backed execution model、no true block disk boot claim、installed disk layout schema / disk id、active slot、boot metadata、persistent state outside rootfs、first-boot replay/local-only、local identity、run id、audit seal、rollback baseline、recovery baseline、no-model-replay、TUI authority false 和 remote dispatch false。该证据明确 `execution_model=projection-backed-initramfs-smoke`、`true_block_disk_boot=false`、`block_device_attached=false`，因为 `RC1-011` 当前仍是 installed disk layout projection，不伪装成 raw block disk boot、EFI/BIOS bootloader execution 或 real GPT partition mounting。task evidence 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-020-installed-system-qemu-smoke.json`。
- `RC1-021` 已完成：installed-system support bundle and recovery evidence projection 已实现为 `scripts/installed-system-support-recovery-projection.ps1`。脚本生成 `.workflow/artifacts/rc1-installed-support-recovery/result.json`（schema `agentos.installed-system-support-recovery-projection-result.v1`，status `passed`，18 checks passed、0 failed、8 个 fail-closed scenarios），并生成 redacted support bundle、recovery projection 和 support index。证据证明 support bundle 能解释 install provenance、local identity、active/inactive slot、persistent state outside rootfs、audit seal、rollback baseline 和 recovery truth，且 `remote_bytes_sent=false`、`remote_authoritative_for_recovery=false`、`no_model_replay=true`、`tui_authority=false`、无 raw secret / raw enrollment token。task evidence 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-021-installed-support-recovery-projection.json`。
- `RC1-022` 已完成：installed-system update rollback drill from inactive slot 已实现为 `scripts/installed-system-rollback-drill.ps1`。脚本生成 `.workflow/artifacts/rc1-installed-rollback-drill/result.json`（schema `agentos.installed-system-rollback-drill-result.v1`，status `passed`，21 checks passed、0 failed、10 个 fail-closed scenarios），并生成 inactive slot update plan、staged candidate、candidate health report 和 rollback report。证据证明 candidate 只 stage 到 inactive slot B，health gate failed 时 activation 被阻塞，active slot A、boot metadata 和 persistent state 不被 in-place mutation，rollback 绑定 first-boot rollback baseline 并恢复 previous active artifact set hash，且 `local_only=true`、`no_model_replay=true`、`tui_authority=false`。task evidence 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-022-installed-rollback-drill.json`。
- `RC1-023` 已完成：install replay、first boot、installer fail-closed fixtures、installed QEMU smoke、support/recovery projection 和 rollback drill 已接入 release provenance、candidate promotion、release reproducibility 和 production signing decision-evidence request。新增 `scripts/verify-rc1-installed-system-release-gate.ps1` 生成 `.workflow/artifacts/release/rc1-installed-system-gate.json`（status `passed`，59 checks，0 failed，0 promotion blockers）；full `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120` 通过，`.workflow/artifacts/release/provenance.json` 中 `promotion.status=promotable` 且 blockers 为 0；`scripts/verify-candidate-promotion.ps1 -OutputPath .workflow/artifacts/candidate-promotion/default-result.json -FailOnBlocked` 通过，776 checks、0 blockers、37 required artifact classes；`scripts/verify-release-reproducibility.ps1 -ArtifactRoot .workflow/artifacts/release-reproducibility-fast -OutputPath .workflow/artifacts/release-reproducibility-fast/result.json` 通过，64 matched fields、0 divergent fields；`scripts/create-production-signing-request.ps1 -RequireDecisionEvidence -FailOnBlocked -OutputPath .workflow/artifacts/production-signing/rc1-023-signing-request.json` 通过，32 required artifacts、32 signing requests、0 blockers。task evidence 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-023-release-provenance-promotion-gate.json`。注意 installed-system smoke 仍是 `projection-backed-initramfs-smoke`，`true_block_disk_boot=false`，不宣称真实 block disk boot。
- `RC1-030` 已完成：Production Distro RC1 final audit and next milestone planning 已写入 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/FINAL-AUDIT-20260531-production-distro-rc1.json` 和 `.workflow/active/WFS-20260530-agentos-production-distro-rc1/docs/final-rc1-closeout-summary.md`。审计结论为 `PASS`，覆盖 `RC1-001` 到 `RC1-023` 共 12 个 pre-closeout task；RC1 installed-system gate 通过 59 个检查且 promotion blockers 为 0；release provenance 为 `promotable` 且 blockers 为 0；candidate promotion 通过 776 个检查且 blockers 为 0；release reproducibility 通过，64 matched fields、0 divergent fields；production signing request 为 `ready-for-external-signer`，32 required artifacts、32 signing requests、0 blockers。RC1 仍不宣称 GA，也不宣称 true block disk boot；下一步进入 Production Distro RC2：true block-device boot and installer execution proof。
- `RC2-001` 已完成：true block-device boot proof contract and bootloader handoff boundary 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc2/docs/true-block-device-boot-contract.md`，task evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-001-true-block-device-boot-contract.json`。契约把 RC1 的 `projection-backed-initramfs-smoke` / `true_block_disk_boot=false` caveat 转成 RC2 acceptance：必须有 deterministic raw disk image、QEMU attached block-device boot、disk-origin boot metadata、active rootfs slot handoff、persistent state mount truth、first-boot seal from disk，并且 projection-backed smoke 不能满足 RC2 promotion。
- `RC2-002` 已完成：installer UX、disk write and offline recovery contract 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc2/docs/installer-ux-disk-write-recovery-contract.md`，task evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-002-installer-ux-disk-write-recovery-contract.json`。契约冻结 operator-visible installer state machine、disk write plan/result schemas、exact consent 绑定 media/target/destructive write/no-activation statement、offline recovery packet 和 fail-closed 条件；disk write 后必须保持 `true_boot_pending=true`，不能把 copy/stage 视为 activation。
- `RC2-003` 已完成：persistent state mount truth and boot recovery boundary 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc2/docs/persistent-state-boot-recovery-boundary.md`，task evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-003-persistent-state-boot-recovery-boundary.json`。契约要求 persistent state mount truth 来自 booted disk，first-boot seal 绑定 disk / slot / state evidence，recovery truth 只能来自 disk write evidence、boot/slot metadata、state mount evidence、RunStore、AuditJournal、first-boot audit seal 和 rollback baseline；remote support、model replay、TUI projection、shell transcript 和 operator memory 都不是 recovery authority。
- `RC2-004` 已完成：block-device installer threat model 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc2/docs/block-device-installer-threat-model.md`，task evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-004-block-device-installer-threat-model.json`。威胁模型覆盖 media/signature/revocation failure、target consent drift、partition tamper、bootloader bypass、state inside rootfs、secret leak、shell/maintainer-script bypass、remote dispatch、TUI mutation、support/recovery authority confusion 和 release gate omission；全部要求 fail closed before target writes where possible、before activation claims always。
- `RC2-010` 已完成：deterministic bootable disk image assembly 已实现为 `scripts/assemble-rc2-bootable-disk-image.ps1`。脚本生成 `.workflow/artifacts/rc2-bootable-disk/agentos-rc2.raw`（16 MiB raw disk，SHA256 `cb8e78e2d4566a17f294bb0ce36d85247df28b6bd281af7addd156ea33f1cd25`）、`.workflow/artifacts/rc2-bootable-disk/bootable-disk-manifest.json`（schema `agentos.bootable-disk-manifest.v1`，status `passed`）和 `.workflow/artifacts/rc2-bootable-disk/result.json`（schema `agentos.rc2-bootable-disk-assembly-result.v1`，17 checks passed、0 failed）。产物包含 protective MBR、primary/backup GPT、partition table metadata、embedded boot/slot/state/install evidence，并明确 `true_block_disk_boot=false`、`qemu_boot_validation_pending=true`，不把 disk assembly 伪装成 RC2 true boot。
- `RC2-011` 已完成：installer replay from install media to bootable disk image with exact consent 已实现为 `scripts/rc2-installer-replay.ps1`。脚本生成 `.workflow/artifacts/rc2-installer-replay/result.json`（schema `agentos.rc2-installer-replay-result.v1`，status `passed`，17 checks passed、0 failed）、`installer-ux-session.json`、`disk-write-plan.json`、`disk-write-result.json`、`offline-recovery-packet.json` 和 target raw disk copy；exact consent 绑定 media id、target id、destructive write 和 no-activation statement，post-write verify 重新绑定 disk / boot / slot / state metadata，且保持 `copy_stage_is_activation=false`、`activation_attempted=false`、`true_block_disk_boot=false`、`qemu_boot_validation_pending=true`。
- `RC2-012` 已完成：true boot and installer fail-closed fixtures 已实现为 `scripts/rc2-block-boot-fail-closed-fixtures.ps1`。脚本生成 `.workflow/artifacts/rc2-block-boot-fail-closed/result.json`（schema `agentos.rc2-block-boot-fail-closed-fixtures.v1`，status `passed`，35 个 failure scenarios、78 checks passed、0 failed），覆盖 install media hash、signature/revocation、target consent drift、partition/GPT tamper、boot metadata bypass、state inside rootfs、secret leak、shell/maintainer bypass、remote dispatch、projection-backed smoke 伪装 true boot、TUI mutation 和 release gate omission；全部保持 `effect_prepared=false`、`activation_attempted=false`、`release_promotion_prepared=false`、`true_block_disk_boot=false`、`qemu_boot_validation_pending=true`。
- `RC2-020` 已完成：QEMU true block-device boot smoke 已实现为 `scripts/rc2-true-block-boot-smoke.ps1`。脚本生成 `.workflow/artifacts/rc2-true-block-boot/result.json`（schema `agentos.true-block-device-boot-smoke.v1`，status `passed`，29 checks passed、0 failed）和 `qemu-serial.log`；QEMU 使用 `-drive file=.workflow/artifacts/rc2-installer-replay/target-agentos-rc2.raw,format=raw,if=ide,media=disk -boot c` 附加 target raw disk，不传入 host `-kernel` 或 `-initrd`，观察到 16 个 boot/runtime/TUI/identity/audit/rollback/recovery markers，并验证 boot / slot / state / install embedded metadata。结果明确 `execution_model=qemu-attached-block-device-boot`、`true_block_disk_boot=true`、`block_device_attached=true`、`projected_initramfs_smoke=false`、`host_kernel_override_used=false`。
- `RC2-021` 已完成：installed block-device support bundle and recovery projection 已实现为 `scripts/rc2-block-support-recovery-projection.ps1`。脚本生成 `.workflow/artifacts/rc2-block-support-recovery/result.json`（schema `agentos.rc2-block-support-recovery-projection-result.v1`，status `passed`，40 checks passed、0 failed、13 个 fail-closed scenarios），并生成 `persistent-state-mount-truth.json`、`first-boot-disk-seal.json`、`boot-recovery-boundary.json`、`support-bundle-redacted.json`、`recovery-projection.json` 和 `support-index.json`。证据证明 support/recovery projection 从 true block-device boot result、installer replay、disk write evidence、offline recovery packet 和 disk metadata 派生；persistent state 来自 booted disk 且 outside rootfs，first-boot seal 绑定 disk / partition / boot / slot / state / RunStore / AuditJournal / rollback baseline；support bundle 为 redacted/local-only，且 `remote_support_authority=false`、`model_replay_authority=false`、`tui_authority=false`、`normal_shell_authority=false`、`recovery_mutation_prepared=false`。
- `RC2-022` 已完成：block-device inactive-slot update rollback drill 已实现为 `scripts/rc2-block-rollback-drill.ps1`。脚本生成 `.workflow/artifacts/rc2-block-rollback-drill/result.json`（schema `agentos.rc2-block-rollback-drill-result.v1`，status `passed`，34 checks passed、0 failed、12 个 fail-closed scenarios），并生成 inactive-slot update plan、inactive-slot staged candidate、candidate health report、rollback report 和 rollback index。证据从 RC2 true block boot、RC2-021 state/seal/recovery projection、installer replay 和 slot metadata 派生，证明候选只面向 inactive slot B，health gate failed 会阻断 activation 和 boot metadata switch，active slot A / persistent state / target disk 均不被 drill mutation，rollback 保持 previous/restored active artifact set hash 一致，且 remote / model / TUI / shell authority 全部为 false。
- `RC2-023` 已完成：true block-device boot evidence 已接入 release provenance、candidate promotion、release reproducibility 和 production signing decision-evidence request。新增 `scripts/verify-rc2-true-block-release-gate.ps1` 生成 `.workflow/artifacts/release/rc2-true-block-release-gate.json`（schema `agentos.rc2-true-block-release-gate.v1`，status `passed`，48 checks、0 failed、0 promotion blockers），要求 bootable disk、installer replay、fail-closed fixtures、true attached block-device boot、support/recovery 和 rollback drill 全部通过，并明确 `projection_backed_installed_smoke=false`、`rc1_projection_smoke_may_satisfy_rc2=false`、`true_block_disk_boot=true`、`block_device_attached=true`、`projected_initramfs_smoke=false`、`host_kernel_override_used=false`。full `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120` 通过，`.workflow/artifacts/release/provenance.json` 中 `promotion.status=promotable`、blockers 为 0 且包含 `true_block_device` 投影；`scripts/verify-candidate-promotion.ps1 -OutputPath .workflow/artifacts/candidate-promotion/default-result.json -FailOnBlocked` 通过，852 checks、0 blockers、76 个 RC2 true-block 相关 blocking checks；`scripts/create-production-signing-request.ps1 -RequireDecisionEvidence -FailOnBlocked -OutputPath .workflow/artifacts/production-signing/rc2-023-signing-request.json` 通过，41 required artifacts、41 signing requests、0 blockers，且包含 9 个 RC2 required artifacts；`scripts/verify-release-reproducibility.ps1 -ArtifactRoot .workflow/artifacts/release-reproducibility-fast -OutputPath .workflow/artifacts/release-reproducibility-fast/result.json` 通过，75 matched fields、0 divergent fields，并比较 `rc2_true_block_release_gate.canonical` 和 `true_block_device.canonical`。负向验证 `scripts/build-release.ps1 -ArtifactDir .workflow/artifacts/rc2-023-skip-gate-negative/release -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120 -SkipRc2TrueBlockReleaseGate` 按预期以 `rc2-true-block-release-gate-skipped` 阻断 promotion。task evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-023-release-provenance-promotion-gate.json`。
- `RC2-030` 已完成：Production Distro RC2 final audit and next milestone planning 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/FINAL-AUDIT-20260531-production-distro-rc2.json` 和 `.workflow/active/WFS-20260531-agentos-production-distro-rc2/docs/final-rc2-closeout-summary.md`。审计结论为 `PASS`，覆盖 `RC2-001` 到 `RC2-023` 共 11 个 pre-closeout task；RC2 true block release gate 通过 48 个检查且 promotion blockers 为 0；release provenance 为 `promotable` 且 blockers 为 0，并明确 `true_block_disk_boot=true`、`block_device_attached=true`、`projected_initramfs_smoke=false`；candidate promotion 通过 852 个检查且 blockers 为 0；release reproducibility 通过，75 matched fields、0 divergent fields；production signing request 为 `ready-for-external-signer`，41 required artifacts、41 signing requests、0 blockers。RC2 仍不宣称 GA；下一步进入 Production Distro RC3：external production signing and release channel publication proof。
- `RC3-001` 已完成：external production signing ceremony and release publication contract 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/docs/external-production-signing-publication-contract.md`，task evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-001-external-production-signing-publication-contract.json`。契约把 RC2 的 `ready-for-external-signer` 状态转成 RC3 acceptance：必须有 secret-safe signing request export、external signer boundary、packaged public keyring / fingerprint / rotation epoch / revocation binding、hash-bound production signature bundle intake、production signatures 覆盖 RC2 true block-device evidence、immutable append-only release channel publication、signed channel consumer smoke、rollback/revocation binding，并保持 `production_ready_claim=false`、TUI projection-only、no local private material for RC3 acceptance。
- `RC3-002` 已完成：production signature bundle intake、custody、rotation and revocation boundary 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/docs/signature-bundle-custody-revocation-boundary.md`，task evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-002-signature-bundle-custody-revocation-boundary.json`。边界冻结 packaged public key custody metadata 为本地唯一 production verification trust source，要求 key id / public fingerprint / rotation epoch / revocation status 在 signing request、bundle、installation 和 cryptographic verification 中一致；bundle verification 必须 hash-bound 当前 signing request 与 signature bundle，拒绝 private/secret-like material、candidate signature、missing/unrequested/duplicate signature、revoked key、rotation drift、非 `.prod.sig.json` target 和 implicit overwrite；local signing fixture 只能用于 rehearsal，不能替代 external ceremony proof。
- `RC3-003` 已完成：immutable release channel publication and rollback boundary 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/docs/release-channel-publication-rollback-boundary.md`，task evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-003-release-channel-publication-rollback-boundary.json`。边界把现有 `agentos.release-channel-metadata.v1` immutable / append-only / content-addressed 模型扩展为 RC3 publication：必须绑定 production signature verification、RC2 true block-device gate、candidate promotion、reproducibility、rollback previous/restored active set、revocation state 和 append-only channel index；publication 不是 rollout 或 activation，consumer smoke 只能从 installed block-device evidence 验证和解释，不能 mutate active slot / boot metadata / active artifact set / production ring。
- `RC3-004` 已完成：production signing and release publication threat model 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/docs/production-signing-publication-threat-model.md`，task evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-004-production-signing-publication-threat-model.json`。威胁模型覆盖 signing request export、external ceremony、public key custody / rotation / revocation、untrusted signature bundle intake、signature installation、production signature verification、immutable publication manifest、append-only channel index、rollback/recovery consumer smoke，以及 TUI / shell / model / remote authority bypass；列出 48 个 required fail-closed scenarios，并明确 signing export、bundle intake、signature installation、publication 和 consumer verification 都不授予 activation / rollout / rollback / shell / model / remote / GA production-ready authority。
- `RC3-010` 已完成：external signing request export package and redaction verifier 已实现为 `scripts/export-external-production-signing-request.ps1`。脚本生成 `.workflow/artifacts/rc3-external-signing-request/result.json`（schema `agentos.rc3-external-signing-request-export-result.v1`，status `passed`，36 checks，0 blockers）、`signing-request.json`、`signing-instructions.json`、`export-manifest.json` 和 `redaction-report.json`；export 绑定 packaged production key `agentos-production-root-v1`、public fingerprint、rotation epoch 和 41 个 required artifacts / signing requests，其中包含 9 个 RC2 true block-device artifact classes；redaction report 通过，`local_private_key_material_used=false`，result 中未出现 local private path、PRIVATE KEY、access_token 或 refresh_token。task evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-010-external-signing-request-export.json`。
- `RC3-011` 已完成：external production signature bundle intake without local private material 已实现为 `scripts/intake-external-production-signature-bundle.ps1`。脚本基于 RC3 external signing request 生成 staged intake request，创建不含 private-key-like 字段的 external structural fixture bundle，运行 packaged keyring verification、signature bundle structural verification 和 staged signature installation；`.workflow/artifacts/rc3-signature-bundle-intake/result.json` 为 schema `agentos.rc3-production-signature-bundle-intake.v1`，status `passed`，19 checks，0 blockers，41 requested / 41 matched / 41 staged signatures，`local_private_key_material_used=false`，`cryptographic_verification_pending=true`。task evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-011-signature-bundle-intake.json`。
- `RC3-012` 已开始：`scripts/verify-production-signatures.ps1 -RequireDecisionEvidence` 已扩展到 RC2 true block-device evidence，并支持通过 `-SigningRequestPath` 消费 RC3 intake staged `.prod.sig.json` targets；新增 `scripts/complete-rc3-production-signature-verification.ps1` 作为真实 external signature bundle / signature values 返回后的完成 runner，只编排 assembly、availability audit、intake 和 cryptographic verification，不生成签名、不读取 private key，并且在 intake 前先执行 bundle availability audit，拒绝旧 local fixture、structural fixture、template placeholder 或 signing request hash 不匹配的 bundle；新增 `scripts/audit-rc3-external-signature-bundles.ps1` 扫描现有 bundle 是否可用于当前 RC3 signing request，并输出逐候选 `rejection_reasons` 与聚合 `rejection_reason_counts`；新增 `scripts/create-rc3-external-signature-bundle-template.ps1` 生成 `.workflow/artifacts/rc3-production-signature-verification/external-signature-bundle-template.json`，为外部签名人提供 41 个 canonical payload / key binding / placeholder signature value 的返回 bundle 模板；新增 `scripts/export-rc3-external-signing-payload-pack.ps1` 导出 `.workflow/artifacts/rc3-production-signature-verification/external-signing-payload-pack/manifest.json` 和 41 个 `.payload.txt`，逐项绑定 canonical payload sha256、artifact hash、key id、public fingerprint 和 rotation epoch；新增 `scripts/assemble-rc3-external-signature-bundle.ps1`，用于把真实外部 `agentos.rc3-external-signature-values.v1` 签名值组装成 return bundle，并拒绝缺失值、placeholder 和非 base64；新增 `scripts/create-rc3-external-signer-handoff.ps1` 生成 `.workflow/artifacts/rc3-production-signature-verification/external-signer-handoff.json`，把 signing request、export manifest、signing instructions、signature-bundle return template、canonical signing payload pack 和 signature-values return template 作为 6 个 outbound files 固化，并声明 `signature_values_schema=agentos.rc3-external-signature-values.v1`、`template_placeholder_allowed=false` 和 assembly command；新增 `scripts/verify-rc3-external-signer-handoff-package.ps1` 验证 handoff package 的 6 个 outbound file hash、41 个 payload 文件、payload pack 与 signing request canonical payload hash 绑定，以及 no sensitive material。当前 `.workflow/artifacts/rc3-production-signature-verification/result.json` 输出 41 个 required artifacts，其中 9 个为 RC2 artifact classes，41 个 staged signature targets 全部被找到并完成 signing request binding；`.workflow/artifacts/rc3-production-signature-verification/completion-result.json` 为 `blocked`，现有 staged diagnostic 仍有 41 个 `crypto_verified` blockers，证明 RC3 structural fixture 不能冒充 cryptographic production signatures；`-SignatureValuesPath` 负向验证 `.workflow/artifacts/rc3-production-signature-verification/signature-values-placeholder-negative/completion-result.json` 在 `signature_bundle_assembly` 阶段即 `blocked`，后续 availability audit / intake / production verification 全部 skipped；`.workflow/artifacts/rc3-production-signature-verification/signature-bundle-availability-audit.json` 为 `blocked`，扫描 5 个候选 bundle、eligible 为 0；external signer handoff 为 `ready-for-external-signer`，33 checks、0 blockers；payload pack 为 `ready-for-external-signer`，41 payloads、89 checks、0 blockers；handoff package verification 为 `passed`，6 outbound files、41 payloads、148 checks、0 blockers；bundle assembly missing-values negative 为 `blocked`（missing values=41），placeholder-values negative 为 `blocked`（placeholder values=41）。blocked evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-012-production-signature-verification-blocked.json`；`RC3-012` 暂不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/create-rc3-external-signature-values-template.ps1`，生成 `.workflow/artifacts/rc3-production-signature-verification/external-signature-values-template.json`（schema `agentos.rc3-external-signature-values.v1`，status `template-ready-for-external-signature-values`，41 signatures / 41 placeholders）；该模板作为 `-SignatureValuesPath` 输入时，`.workflow/artifacts/rc3-production-signature-verification/signature-values-template-negative/completion-result.json` 在 `signature_bundle_assembly` 阶段 blocked，availability audit / intake / production verification 均 skipped。external signer handoff 已更新为 6 outbound files、33 checks、0 blockers；handoff package verification 已更新为 6 outbound files、41 payloads、148 checks、0 blockers。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-external-signature-values.ps1`，作为真实 external signature values 进入 assembly 前的 preflight gate；它验证 schema、signing request hash、bundle template hash、payload pack hash、41 个 artifact name、payload/key/algorithm binding、placeholder、base64 和 secret-like material，不执行 cryptographic verification、不生成签名、不读取 private key。模板负向验证 `.workflow/artifacts/rc3-production-signature-verification/signature-values-template-preflight-negative/result.json` 为 `blocked`，30 checks、1 blocker、41 placeholders；completion runner 现在在 `signature_values_preflight` 阶段先 blocked，后续 assembly / availability audit / intake / production verification 均 skipped。external signer handoff 已更新为 34 checks、0 blockers，并包含 signature values preflight command 与 `-SignatureValuesPath` completion command；handoff package verification 已更新为 151 checks、0 blockers。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-external-signature-values-fail-closed-fixtures.ps1`，生成并验证 11 个 signature values preflight fail-closed 负向夹具，覆盖 invalid base64、duplicate/missing/extra artifact、signing request / template / payload pack hash mismatch、algorithm / key / payload binding mismatch 和 blocked status。聚合结果 `.workflow/artifacts/rc3-production-signature-verification/signature-values-preflight-negatives/result.json` 为 `passed`，11/11 case 均在 preflight blocked 且命中预期 blocker id；该 harness 不执行 cryptographic signing / verification、不读取 private key，fixture inputs 不能作为 production signatures。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-external-signature-values-completion-fail-closed-fixtures.ps1`，复用 11 个 preflight negative signature values 输入走完整 completion runner；聚合结果 `.workflow/artifacts/rc3-production-signature-verification/signature-values-completion-negatives/result.json` 为 `passed`，11/11 case 均为 `signature_values_preflight:blocked`，并且 `signature_values_receipt`、`signature_bundle_assembly`、`signature_bundle_availability_audit`、`signature_bundle_intake` 和 `production_signature_verification` 全部 skipped，没有任何下游 step passed。该 harness 不执行 cryptographic signing / verification、不读取 private key。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-external-signature-values-crypto-fail-closed-fixtures.ps1`，生成结构有效、41 个 base64 signature values 但非真实 RSA signatures 的 values 输入，走完整 completion runner。该路径证明 `signature_values_preflight:passed`、`signature_values_receipt:passed`、`signature_bundle_assembly:assembled`、`signature_bundle_availability_audit:passed`、`signature_bundle_intake:passed`，最终 `production_signature_verification:blocked`，41 个 required artifacts / 9 个 RC2 true block artifacts 均覆盖，`crypto_verified_blockers=41` 且 `missing_signature_blockers=0`。同时修正 `scripts/assemble-rc3-external-signature-bundle.ps1`，assembled production bundle 不再携带 assembly diagnostic checks / blockers，避免 diagnostic message 中的 sensitive detector 文本触发 intake 的 no-private-fields gate；diagnostics 仍保留在 assembly result 中。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增并扩展 `scripts/verify-rc3-external-signature-bundle-fail-closed-fixtures.ps1`，生成并验证 returned signature bundle completion-path 负向夹具，覆盖 template bundle、signing request hash mismatch、structural fixture、local fixture、not external boundary、missing required signature、extra signature、placeholder signature，以及 missing bundle file、invalid JSON bundle file 和 unsupported schema direct input-path cases。聚合结果 `.workflow/artifacts/rc3-production-signature-verification/signature-bundle-completion-negatives/result.json` 为 `passed`，11/11 cases blocked（含 `input_path_negative_cases=3`），均在 `signature_bundle_availability_audit:blocked` 后让 `signature_bundle_receipt`、`signature_bundle_intake` 和 `production_signature_verification` 保持 skipped，且没有任何下游 step passed。该 harness 不执行 cryptographic signing / verification、不读取 private key，fixture bundles 不能作为 production signatures。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增并更新 `scripts/audit-rc3-012-completion-gate.ps1`，作为不可误完成 gate audit；它同时检查 active plan 仍停在 `RC3-012`、`RC3-013` 未开始、production completion / verification 仍 blocked、41 个 required artifacts 与 9 个 RC2 true block-device artifacts 仍覆盖、41 个 `crypto_verified` blockers 仍存在、external signer handoff package 通过，以及 42 个 fail-closed negative cases（11 preflight、11 completion-path signature values、1 values crypto-negative、8 completion-path bundles、1 crypto-negative returned bundle、10 outbound package tamper/path/hash/secret negatives）全部通过。结果 `.workflow/artifacts/rc3-production-signature-verification/rc3-012-completion-gate-audit/result.json` 为 `passed`，`checks=62`、`blockers=0`，但明确 `rc3_012_complete=false`、`rc3_012_may_advance=false`。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-external-signature-bundle-crypto-fail-closed-fixtures.ps1`，生成一个结构完整、external boundary、当前 signing request hash 匹配、41 个 signature value 都是 base64 但并非真实 RSA signature 的 returned bundle。该 bundle 通过 availability audit、hash-only signature bundle receipt 和 signature bundle intake，成功 stage 41 个 `.prod.sig.json` 到专用 artifact dir，但 `.workflow/artifacts/rc3-production-signature-verification/signature-bundle-crypto-negative/production-signature-verification.json` 在 cryptographic verification 阶段 blocked，41 个 required artifacts / 9 个 RC2 true block artifacts 均覆盖，`crypto_verified_blockers=41` 且 `missing_signature_blockers=0`。聚合结果 `.workflow/artifacts/rc3-production-signature-verification/signature-bundle-crypto-negative/result.json` 为 `passed`，`steps=4`，顺序为 `signature_bundle_availability_audit:passed`、`signature_bundle_receipt:passed`、`signature_bundle_intake:passed`、`production_signature_verification:blocked`。该 harness 不执行 cryptographic signing、不读取 private key，并对临时 keyring verification artifact 做 redaction 以避免 private path 文本进入证据。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/export-rc3-external-signer-outbound-package.ps1`，把 external signer handoff control、6 个 outbound files 和 41 个 canonical payload files 复制到 `.workflow/artifacts/rc3-production-signature-verification/external-signer-outbound-package/package`，生成 hash-bound manifest 和 result。结果 `.workflow/artifacts/rc3-production-signature-verification/external-signer-outbound-package/result.json` 为 `passed`，`package_content_files=48`、`outbound_files=6`、`payload_files=41`、`checks=152`、`blockers=0`，secret scan passed，且 `cryptographic_signing_performed=false`、`local_private_key_material_used=false`。新增并修复 `scripts/verify-rc3-external-signer-outbound-package.ps1`，只读重算 package content hash、核对 48 个实际文件、1 个 handoff control、6 个 outbound files、41 个 payload files、manifest/result hash、package-internal handoff / signing request / payload pack 自洽性和 clean secret scan；该历史 checkpoint 的 verifier result 为 `passed`、`checks=182`、`blockers=0`、payload binding mismatches 为 0，后续已被当前 `190` checks read-boundary summary superseded。新增 `scripts/verify-rc3-external-signer-outbound-package-fail-closed-fixtures.ps1`，生成并验证 10 个 outbound package fail-closed 负向夹具，覆盖 payload tamper、secret marker、manifest payload hash drift、missing / extra file、handoff outbound hash drift、manifest / result content hash drift、result manifest hash drift 和 package path escape；聚合结果 `.workflow/artifacts/rc3-production-signature-verification/external-signer-outbound-package-negatives/result.json` 为 `passed`，10/10 case 均被 package verifier blocked。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/archive-rc3-external-signature-values-receipt.ps1`，在真实 external `agentos.rc3-external-signature-values.v1` 返回后先运行 preflight，再生成 hash-only custody receipt；receipt 只保留每个 artifact 的 `signature_value_sha256`、payload path/hash、key id、public fingerprint、rotation epoch、source values/signing request/template/payload pack/preflight hashes，不归档 raw signature value，不执行 signing / production crypto verification，也不读取 local private material。completion runner 现在在 `signature_values_preflight` 通过后、bundle assembly 前强制生成 `signature_values_receipt`。独立 receipt `.workflow/artifacts/rc3-production-signature-verification/external-signature-values-receipt/result.json` 为 `passed`，41 signatures / 41 hash entries；signature values crypto-negative 路径现在证明 `signature_values_preflight:passed`、`signature_values_receipt:passed`、`signature_bundle_assembly:assembled`、`signature_bundle_availability_audit:passed`、`signature_bundle_intake:passed`、`production_signature_verification:blocked`。`scripts/audit-rc3-012-completion-gate.ps1` 已接入 receipt readiness；gate audit 现在 `checks=68`、`blockers=0`、`fail_closed_negative_cases=42`，仍明确 `rc3_012_complete=false`、`rc3_012_may_advance=false`。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-external-signature-values-receipt-fail-closed-fixtures.ps1`，复用 11 个 preflight negative signature values 输入并增加 missing signature values file case，验证 receipt 在 preflight blocked 或输入缺失时全部 blocked，且所有 blocked receipt result 都不归档 raw `signature_value` 字段。聚合结果 `.workflow/artifacts/rc3-production-signature-verification/signature-values-receipt-negatives/result.json` 为 `passed`，12/12 cases passed、`raw_signature_value_fields=0`；`scripts/audit-rc3-012-completion-gate.ps1` 已接入 receipt negatives，gate audit 现在 `checks=72`、`blockers=0`、`fail_closed_negative_cases=54`，仍明确 `rc3_012_complete=false`、`rc3_012_may_advance=false`。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-external-signature-values-inbound-package.ps1`，把 external returned signature values 进入 completion 前的 inbound custody 验收固化为可复跑证据：它验证 returned values 位于预期 inbound artifact root、绑定当前 outbound package content hash / signing request / bundle template / payload pack、先跑 preflight、再生成 hash-only receipt，且不归档 raw `signature_value`、不执行 signing / production crypto verification、不读取 local private material、不声明 production-ready。默认 fixture 结果 `.workflow/artifacts/rc3-production-signature-verification/external-signature-values-inbound-verification/result.json` 为 `passed`，`checks=44`、41 signatures、receipt hash entries=41、`raw_signature_value_fields=0`、`production_signature_verification_ready=false`。新增 `scripts/verify-rc3-external-signature-values-inbound-fail-closed-fixtures.ps1`，覆盖 path outside inbound root、missing signature values file、signing request hash drift、outbound package verification blocked 4 个负向场景；聚合结果 `.workflow/artifacts/rc3-production-signature-verification/signature-values-inbound-negatives/result.json` 为 `passed`，4/4 cases blocked、`raw_signature_value_fields=0`。`scripts/audit-rc3-012-completion-gate.ps1` 已接入 inbound verification 和 inbound negatives，gate audit 现在 `checks=83`、`blockers=0`、`fail_closed_negative_cases=58`，仍明确 `rc3_012_complete=false`、`rc3_012_may_advance=false`。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-external-signature-bundle-inbound-package.ps1`，把 direct returned external signature bundle 进入 intake 前的 inbound custody 验收固化为可复跑证据：它验证 returned bundle 位于预期 inbound artifact root、绑定 verified outbound package content hash / current signing request / return bundle template，运行 availability audit 和 production signature bundle structural verifier，但不安装签名、不执行 production crypto verification、不归档 raw bundle signature value、不读取 local private material、不声明 production-ready。默认 crypto-negative returned bundle 结果 `.workflow/artifacts/rc3-production-signature-verification/external-signature-bundle-inbound-verification/result.json` 为 `passed`，`checks=45`、41 signatures、availability `passed`、bundle verification `ready-for-cryptographic-verification`、matched signatures=41、`raw_bundle_signature_value_fields=0`、`production_signature_verification_ready=false`。新增 `scripts/verify-rc3-external-signature-bundle-inbound-fail-closed-fixtures.ps1`，覆盖 path outside inbound root、missing signature bundle file、signing request hash drift、outbound package verification blocked 4 个负向场景；聚合结果 `.workflow/artifacts/rc3-production-signature-verification/signature-bundle-inbound-negatives/result.json` 为 `passed`，4/4 cases blocked、`raw_bundle_signature_value_fields=0`。`scripts/audit-rc3-012-completion-gate.ps1` 已接入 bundle inbound verification 和 bundle inbound negatives，gate audit 现在 `checks=94`、`blockers=0`、`fail_closed_negative_cases=62`，仍明确 `rc3_012_complete=false`、`rc3_012_may_advance=false`。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/archive-rc3-external-signature-bundle-receipt.ps1`，把 direct returned external signature bundle 进入 intake 前的 hash-only custody receipt 固化为可复跑证据；receipt 先运行 availability audit，再记录 41 个 `signature_value_sha256`，不归档 raw signature values，不执行 signing / production crypto verification，不读取 local private material，不声明 production-ready。默认 receipt `.workflow/artifacts/rc3-production-signature-verification/external-signature-bundle-receipt/result.json` 为 `passed`，`checks=23`、41 signatures / 41 hash entries、`raw_signature_values_archived=false`。`scripts/complete-rc3-production-signature-verification.ps1` 和 `scripts/verify-rc3-external-signature-bundle-crypto-fail-closed-fixtures.ps1` 均已接入 `signature_bundle_receipt`，并证明 direct bundle 路径在 intake 前先写 hash-only receipt；`scripts/audit-rc3-012-completion-gate.ps1` 现在强制检查 receipt-before-intake 顺序、receipt hash-only 和 no-signing/no-production-claim，gate audit 为 `passed`，`checks=102`、`blockers=0`、`fail_closed_negative_cases=62`，仍明确 `rc3_012_complete=false`、`rc3_012_may_advance=false`。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-external-signature-bundle-receipt-fail-closed-fixtures.ps1`，为 direct returned bundle receipt 增加 fail-closed 负向证据，覆盖 template bundle、signing request hash mismatch、structural fixture、local fixture、not external boundary、missing required signature、extra signature、placeholder signature、invalid base64 signature 和 missing signature bundle file。聚合结果 `.workflow/artifacts/rc3-production-signature-verification/signature-bundle-receipt-negatives/result.json` 为 `passed`，10/10 cases blocked、`raw_signature_value_fields=0`；其中 invalid base64 case 证明 availability audit 可以 passed，但 receipt 自身仍会 blocked。`scripts/audit-rc3-012-completion-gate.ps1` 已接入 bundle receipt negatives，gate audit 现在 `checks=106`、`blockers=0`、`fail_closed_negative_cases=72`，仍明确 `rc3_012_complete=false`、`rc3_012_may_advance=false`。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：更新 `scripts/create-rc3-external-signer-handoff.ps1`，把 returned signature values 和 direct returned bundle 的 inbound custody verifier command、hash-only receipt command 明确写入 external signer handoff；`scripts/verify-rc3-external-signer-handoff-package.ps1` 与 `scripts/verify-rc3-external-signer-outbound-package.ps1` 现在强制校验这些命令存在，并证明 inbound acceptance 只是 custody readiness，不执行 signing / production crypto verification、不读取 local private material、不声明 production-ready。该历史 checkpoint 当时重跑结果为 handoff `ready-for-external-signer`、38 checks，handoff package verification `passed`、162 checks，outbound package verification `passed`、185 checks、48 actual files，outbound package negatives `passed`、10/10 cases blocked；这些 verifier counts 已被当前 `190` checks read-boundary summary superseded。`scripts/audit-rc3-012-completion-gate.ps1` 现在要求 handoff inbound acceptance commands，gate audit 为 `passed`、`checks=107`、`blockers=0`、`fail_closed_negative_cases=72`，仍明确 `rc3_012_complete=false`、`rc3_012_may_advance=false`。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/audit-rc3-external-signer-exchange-freshness.ps1`，只读证明 current signing request、handoff、payload pack、signature bundle / values return templates、outbound package result / manifest / verification，以及 returned values / returned bundle inbound custody evidence 全部绑定同一个当前 outbound package content hash，避免 stale inbound evidence 继续引用旧 package hash。重跑结果：exchange freshness audit `passed`、40 checks、`exchange_fresh=true`、content hash `8a118aac78fa2a4500fbb4b855f45abb2f7ec059db5bd723fd1ed0b04b9f9686`、secret scan hits=0；`scripts/audit-rc3-012-completion-gate.ps1` 已把 freshness audit 接入 blocking gate，gate audit 为 `passed`、`checks=114`、`blockers=0`、`fail_closed_negative_cases=72`、`external_signer_exchange_fresh=true`，仍明确 `rc3_012_complete=false`、`rc3_012_may_advance=false`。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-external-signer-exchange-freshness-fail-closed-fixtures.ps1`，为 exchange freshness 增加 9 个 fail-closed 负向场景，覆盖 values inbound stale content hash、bundle inbound stale content hash、values inbound stale outbound verification hash、handoff signing request drift、payload pack hash drift、bundle template hash drift、values template hash drift、blocked outbound package verification 和 handoff sensitive marker。聚合结果 `.workflow/artifacts/rc3-production-signature-verification/external-signer-exchange-freshness-negatives/result.json` 为 `passed`，9/9 cases blocked、`result_secret_scan_hits=0`；`scripts/audit-rc3-012-completion-gate.ps1` 已接入 freshness negatives，gate audit 为 `passed`、`checks=118`、`blockers=0`、`fail_closed_negative_cases=81`、`external_signer_exchange_freshness_negative_cases=9`，仍明确 `rc3_012_complete=false`、`rc3_012_may_advance=false`。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增只读 audit `scripts/audit-rc3-external-signer-secret-safety.ps1`，集中证明 external signer exchange evidence、handoff / outbound package、exchange freshness、hash-only receipts、values / bundle inbound verification 和 inbound negatives 不泄漏 private authority path、private key PEM、token field 或 raw `signature_value` 字段。结果 `.workflow/artifacts/rc3-production-signature-verification/external-signer-secret-safety/result.json` 为 `passed`，25 checks、0 blockers、64 files scanned、48 outbound package files scanned、`forbidden_marker_hits=0`、`raw_signature_value_field_hits=0`；该 audit 不签名、不执行 production crypto verification、不读取 local private material、不归档 raw signature values、不声明 production-ready，且明确 `rc3_012_complete=false`、`rc3_012_may_advance=false`。`scripts/audit-rc3-012-completion-gate.ps1` 已接入 secret-safety result，重跑 gate 为 `passed`、125 checks、0 blockers、81 fail-closed negative cases、secret-safety checks=25、secret marker/raw signature field hits 均为 0，仍保持 `current_task=RC3-012`、`RC3-012=next`、`RC3-013=completed`。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增只读 audit `scripts/audit-rc3-external-return-readiness.ps1`，证明真实 external signature values 或 direct returned bundle 到达后已有已验证的入口链路：handoff 发布 values / bundle inbound verifier、hash-only receipt 和 completion commands；outbound package 48 files / 6 outbound files / 41 payload files 已验证；exchange freshness 绑定当前 outbound package content hash；values 和 bundle 两条 return path 均 `ready=true`，并覆盖 49 个 values-path negative cases 与 27 个 bundle-path negative cases。结果 `.workflow/artifacts/rc3-production-signature-verification/external-return-readiness/result.json` 为 `passed`，42 checks、0 blockers、`external_return_intake_ready=true`、`values_return_path_ready=true`、`bundle_return_path_ready=true`，但仍明确 `production_signature_verification_ready=false`、`rc3_012_complete=false`、`rc3_012_may_advance=false`。readiness-only completion gate 当时通过且保持 `current_task=RC3-012`、`RC3-012=next`、`RC3-013=completed`；最新 gate 状态见下一条 inbox audit。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增只读 inbox audit `scripts/audit-rc3-external-return-inbox.ps1`，扫描 `.workflow/artifacts/rc3-production-signature-verification/external-return-inbox/drop` 中等待外部签名人返回的 JSON 候选，只做发现和分类，不签名、不执行 production crypto verification、不归档 raw signature values、不读取 local private material、不声明 production-ready。当前 `.workflow/artifacts/rc3-production-signature-verification/external-return-inbox/result.json` 为 `passed`，12 checks、0 blockers、0 json candidates、0 rejected candidates、`external_return_detected=false`、`completion_runner_candidate_ready=false`；新增 `scripts/verify-rc3-external-return-inbox-fail-closed-fixtures.ps1`，覆盖 invalid JSON、unsupported schema、values / bundle signing request hash drift、placeholder、missing required signature、invalid base64、sensitive marker 和 non-external boundary 等 12 个 inbox negative cases，`.workflow/artifacts/rc3-production-signature-verification/external-return-inbox-negatives/result.json` 当时为 `passed`、12/12 cases blocked、raw signature value field counts 为 0；该历史 checkpoint 已被最新 23-case 聚合的 fixture input raw fields=329/370 且 `raw_signature_values_archived=false` 语义覆盖。completion gate 当时接入 inbox audit 和 inbox negatives 后为 `passed`、140 checks、93 fail-closed negative cases，仍保持 `rc3_012_complete=false`、`rc3_012_may_advance=false`；最新 gate 状态见后续记录。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-external-return-inbox-candidate-readiness.ps1`，把既有 values crypto-negative fixture 和 direct returned bundle crypto-negative fixture 放入隔离 inbox，验证 inbox audit 能把两类结构有效但非真实 production proof 的返回文件分别分类为 `ready-for-values-inbound` 和 `ready-for-bundle-inbound` completion-runner candidates。结果 `.workflow/artifacts/rc3-production-signature-verification/external-return-inbox-candidate-readiness/result.json` 为 `passed`，1 case、2 json candidates、1 values candidate、1 bundle candidate、`completion_runner_candidate_ready=true`，同时仍明确 `production_signature_verification_ready=false`、`rc3_012_complete=false`、`rc3_012_may_advance=false`；该 harness 不签名、不执行 production crypto verification、不读取 local private material、不归档 raw signature values、不声明 production-ready。completion gate 已接入 candidate-readiness，当时为 `passed`、146 checks、93 fail-closed negative cases；最新 gate 状态见下一条 completion-candidates 记录。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-external-return-inbox-completion-candidates-fail-closed-fixtures.ps1`，把 inbox audit 已能识别的 values / bundle completion-runner candidates 放入隔离 completion runner，证明两类结构有效但非真实 production signature 的返回仍必须在 production cryptographic verification 阶段 fail closed。结果 `.workflow/artifacts/rc3-production-signature-verification/external-return-inbox-completion-candidates/result.json` 为 `passed`，2/2 cases passed、2 个 completion-runner candidate-ready cases、2 个 production crypto-blocked cases、82 个 `crypto_verified` blockers、`rc3_012_complete=false`、`rc3_012_may_advance=false`。completion gate 已接入该 harness，后续 child audit exit-code contract、visible/hidden non-JSON inbox fail-closed 加固后的当时 gate 状态为 `passed`、156 checks、97 fail-closed negative cases，并仍保持 `current_task=RC3-012`、`RC3-012=next`、`RC3-020` 到 `RC3-023` planned；该历史 checkpoint 已被后续 inbox 和 completion-runner exclusivity 记录 supersede。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：加固 `scripts/verify-rc3-external-return-inbox-fail-closed-fixtures.ps1` 与 `scripts/verify-rc3-external-return-inbox-candidate-readiness.ps1`，在每次调用 child inbox audit 前重置 `$LASTEXITCODE`，并把 child audit exit code 纳入 case pass 条件，避免同一 PowerShell 进程中的陈旧 exit code 污染 fail-closed 证据。重跑 inbox negatives 在 visible/hidden non-JSON hardening 后为 `passed`、14/14 cases blocked（含 unsupported non-JSON inbox file 与 unsupported hidden non-JSON inbox file）、raw signature value field counts 当时为 0；该历史 checkpoint 已被最新 23-case 聚合的 fixture input raw fields=329/370 且 `raw_signature_values_archived=false` 语义覆盖。candidate-readiness 仍为 `passed`、1 case、2 json candidates、`completion_runner_candidate_ready=true`。当时 RC3-012 gate 为 `passed`、156 checks、97 fail-closed negative cases，RC3-013 aggregate 为 `passed`、58 checks、97 fail-closed negative cases，下游 RC3-020/021/022/023/030 precondition evidence 均保持预期 blocked/pass；后续 reparse point directory、inbox root reparse point、outside inbox root no-create、invalid-json、unsupported-schema raw/sensitive hygiene、同类型多候选 inbox 和 completion runner 双输入加固已刷新到 117/23。`plan.json` 仍保持 `current_task=RC3-012`、`RC3-012=next`、后续 publication wave planned。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：加固 `scripts/complete-rc3-production-signature-verification.ps1`，在 completion runner 每个 child step 执行前重置 `$LASTEXITCODE`，避免前一个 PowerShell native 命令退出码污染 `signature_values_preflight`、receipt、assembly、availability audit、intake 或 production signature verification step 的判定。重跑 external return inbox completion-candidates 仍为 `passed`、2/2 cases passed、2 个 production crypto-blocked cases、82 个 `crypto_verified` blockers；当时 RC3-012 completion gate 为 `passed`、156 checks、97 fail-closed negative cases、`rc3_012_complete=false`、`rc3_012_may_advance=false`；RC3-013 aggregate 为 `passed`、58 checks、97 fail-closed negative cases；下游 RC3-020/021/022/023/030 precondition evidence 均刷新并保持预期 blocked/pass。`plan.json` 仍保持 `current_task=RC3-012`、`RC3-012=next`、后续 publication wave planned。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：加固 `scripts/archive-rc3-external-signature-values-receipt.ps1`、`scripts/archive-rc3-external-signature-bundle-receipt.ps1` 以及两个 receipt fail-closed harness，在调用 child preflight、availability audit 或 receipt script 前重置 `$LASTEXITCODE`，避免 hash-only receipt evidence 误读陈旧 native exit code。重跑 signature values receipt negatives 仍为 `passed`、12/12 cases passed、raw signature value fields=0；signature bundle receipt negatives 仍为 `passed`、10/10 cases passed、raw signature value fields=0；completion-candidates 仍为 `passed`、2/2 cases passed、82 个 `crypto_verified` blockers；当时 RC3-012 gate 为 `passed`、156 checks、97 fail-closed negative cases，RC3-013 aggregate 为 `passed`、58 checks、97 fail-closed negative cases；下游 RC3-020/021/022/023/030 precondition evidence 均刷新并保持预期 blocked/pass。`plan.json` 仍保持 `current_task=RC3-012`、`RC3-012=next`、后续 publication wave planned。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：加固 external return inbox audit 对 hidden JSON returned values/bundle、同类型多 eligible return files、inbox root 的创建前校验、普通子目录、reparse point directory 和 inbox root reparse point 的处理，`scripts/audit-rc3-external-return-inbox.ps1` 现在先拒绝越界 inbox root，再拒绝 inbox root reparse point，并把 drop 下的普通 directory candidate 作为 `unsupported_directory`、reparse point candidate 作为 `unsupported_reparse_point` fail closed，不读取、不遍历目录或 reparse target 内容；同一 signing request 下多个 eligible signature-values 或多个 eligible signature-bundle return files 会以 `inbox.no_multiple_signature_values_returns` / `inbox.no_multiple_signature_bundle_returns` 阻断，且 `completion_runner_candidate_ready=false`。`scripts/verify-rc3-external-return-inbox-fail-closed-fixtures.ps1` 覆盖 `hidden-signature-values-json-file`、`hidden-signature-bundle-json-file`、`multiple-signature-values-json-files`、`multiple-signature-bundle-json-files`、`unsupported-directory`、`unsupported-reparse-point-directory`、`unsupported-reparse-point-inbox-root` 和 `outside-inbox-root-no-create` 夹具。该历史 checkpoint 还让 malformed JSON candidate 和 unsupported-schema candidate 在拒绝前仍记录 `secret_safe=false`、`raw_signature_value_fields=1`、`raw_bundle_signature_value_fields=1`；invalid JSON 以 `invalid_json` + `forbidden_marker` fail closed，unsupported schema 以 `unsupported_schema` + `forbidden_marker` fail closed，不归档 raw signature values。重跑 inbox audit 为 `passed`、16 checks、0 blockers、0 hidden file candidates、0 directory candidates、0 reparse point candidates、0 ambiguous return candidates；inbox negatives 为 `passed`、23/23 cases blocked，fixture input raw field counts 为 `raw_signature_value_fields=329` / `raw_bundle_signature_value_fields=370`，且 blocked artifacts 仍保持 `raw_signature_values_archived=false`、child audit exit 0 cases=23，outside drop directory 未创建。后续 completion runner 双输入、mode exclusivity、missing input、direct returned values input-path、direct returned bundle input-path、local signature external-boundary negative 和 local signature values boundary negative 加固后的当时 RC3-012 gate 为 `passed`、161 checks、123 fail-closed negative cases、external return inbox negative cases=23、`rc3_012_complete=false`、`rc3_012_may_advance=false`；当时 RC3-013 aggregate 为 `passed`、61 checks、123 fail-closed negative cases；这些 gate / aggregate counts 已被后续 `185/153` 与 `70/153` current summary superseded。`plan.json` 仍保持 `current_task=RC3-012`、`RC3-012=next`、后续 publication wave planned。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：加固 `scripts/complete-rc3-production-signature-verification.ps1` 的 completion mode contract；当调用方使用 `-UseExistingStagedSignatures` 时同时提供 `-SignatureValuesPath` 或 `-SignatureBundlePath`，completion runner 现在在任何 preflight、hash-only receipt、assembly、availability audit、intake 或 production crypto verification 之前以 `signature_inputs.mode_mutually_exclusive` fail closed，避免诊断模式和外部返回输入混用。`scripts/verify-rc3-external-signature-values-completion-fail-closed-fixtures.ps1` 新增 `existing-staged-mode-with-signature-values-input` 和 `existing-staged-mode-with-signature-bundle-input` negative cases；该 checkpoint 当时为 `passed`、14/14 cases passed、11 个 preflight completion negatives、1 个 input exclusivity case、2 个 mode exclusivity cases，3 个 exclusivity cases downstream steps 均为空。后续 missing input、direct returned values input-path 和 local signature values boundary negative 加固已把当前 completion negatives 提升到 19/19。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：加固 completion runner 的 required-input contract；当调用方既不提供 `-SignatureValuesPath` / `-SignatureBundlePath`，也不使用 `-UseExistingStagedSignatures` 时，completion runner 现在被 `scripts/verify-rc3-external-signature-values-completion-fail-closed-fixtures.ps1` 聚合覆盖，并要求以 `signature_bundle.required` fail closed，且不运行任何 downstream preflight、receipt、assembly、availability audit、intake 或 production crypto verification step。新增 `missing-completion-inputs` negative case 后，signature values completion result 当时为 `passed`，共 15 cases passed、11 个 preflight completion negatives、1 个 required input case、1 个 input exclusivity case、2 个 mode exclusivity cases，所有 input/mode/required contract cases downstream steps 均为空。后续 direct returned values / bundle input-path hardening、local signature external-boundary negative 和 local signature values boundary negative 当时把 RC3-012 gate 提升为 `passed`、161 checks、123 fail-closed negative cases，RC3-013 aggregate 为 `passed`、61 checks、123 fail-closed negative cases；这些 counts 已被后续 current summary superseded。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：加固 direct returned `-SignatureBundlePath` input contract，`scripts/verify-rc3-external-signature-bundle-fail-closed-fixtures.ps1` 新增 `missing-bundle-file`、`invalid-json-bundle-file` 和 `unsupported-schema-bundle-file` 3 个 completion-path negative cases，证明不存在文件、非法 JSON 或 unsupported schema 均不能进入 receipt / intake / production crypto verification。当前 `.workflow/artifacts/rc3-production-signature-verification/signature-bundle-completion-negatives/result.json` 为 `passed`、11/11 cases passed、`input_path_negative_cases=3`；后续 direct returned values input-path hardening、local signature external-boundary negative 和 local signature values boundary negative 当时把 RC3-012 gate 提升为 `passed`、161 checks、123 fail-closed negative cases，RC3-013 aggregate 为 `passed`、61 checks、123 fail-closed negative cases；这些 counts 已被后续 current summary superseded，且 `RC3-012` 仍因 41 个 `crypto_verified` blockers 不能标记完成。
- `RC3-012` 继续推进：加固 direct returned `-SignatureValuesPath` input contract，`scripts/verify-rc3-external-signature-values-completion-fail-closed-fixtures.ps1` 新增 `missing-signature-values-file`、`invalid-json-signature-values-file` 和 `unsupported-schema-signature-values-file` 3 个 completion-path negative cases，证明不存在文件、非法 JSON 或 unsupported schema 均不能进入 hash-only receipt、bundle assembly、availability audit、intake 或 production crypto verification。当前 `.workflow/artifacts/rc3-production-signature-verification/signature-values-completion-negatives/result.json` 为 `passed`、19/19 cases passed、`input_path_negative_cases=3`；加入 local signature external-boundary negative 和 local signature values boundary negative 后，当时 RC3-012 gate 为 `passed`、161 checks、123 fail-closed negative cases，RC3-013 aggregate 为 `passed`、61 checks、123 fail-closed negative cases；这些 counts 已被后续 current summary superseded，且 `RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/verify-rc3-local-signature-bundle-external-boundary-fail-closed.ps1`，把“我们自己做 Signature”的现有 local release authority fixture 固化为 external-boundary 负向 probe。脚本调用 `scripts/create-local-production-signature-bundle.ps1` 为当前 RC3 signing request 生成 41-signature local bundle，明确 `production_ready_claim=false`、`local_private_key_material_used=true`、`cryptographic_signing_performed=true`，随后把该 bundle 送入 RC3 completion runner；结果 `.workflow/artifacts/rc3-production-signature-verification/local-signature-boundary-negative/result.json` 为 `passed`、1/1 case passed，availability audit 以 `not_external_boundary` 和 `local_fixture` 拒绝，eligible external bundles=0，receipt / intake / production verification 均 skipped，`rc3_012_complete=false`、`rc3_012_may_advance=false`。
- `RC3-012` 继续推进：加固 standalone returned bundle inbound custody verifier 的 local-boundary 负向覆盖。`scripts/verify-rc3-external-signature-bundle-inbound-fail-closed-fixtures.ps1` 现在读取 local signature boundary probe 产生的真实 41-signature local bundle，并新增 `local-signature-bundle-boundary` case，证明 `scripts/verify-rc3-external-signature-bundle-inbound-package.ps1` 会以 `signature_bundle.external_boundary`、`signature_bundle.no_local_private_material` 和 `availability.passed` 阻断该 bundle，`inbound_acceptance_ready=false`，且 result / aggregate 均不归档 raw bundle signature values。该 inbound aggregate 为 `passed`、5/5 cases；该历史 checkpoint 后续曾把 external return readiness values-path negatives 提升到 49、bundle-path negatives 保持 27，并把 RC3-012 gate 刷新到 123 fail-closed negative cases；这些 counts 已被后续 current summary superseded。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：加固 hash-only bundle receipt 对真实 local signed bundle 的 external-boundary 负向覆盖。`scripts/verify-rc3-external-signature-bundle-receipt-fail-closed-fixtures.ps1` 现在读取 local signature boundary probe 产生的真实 41-signature bundle，并新增 `local-signature-bundle-boundary` case，证明 `scripts/archive-rc3-external-signature-bundle-receipt.ps1` 会在 custody archival 前以 `availability.passed`、`signature_bundle.external_boundary` 和 `signature_bundle.no_local_private_material` 阻断该 bundle；availability audit 同时记录 `not_external_boundary` 和 `local_fixture`，receipt negative aggregate 为 `passed`、11/11 cases、`raw_signature_value_fields=0`。该历史 checkpoint 当时重跑 external return readiness 为 `passed`、49 values negatives / 27 bundle negatives；RC3-012 gate 为 `passed`、161 checks、123 fail-closed negative cases；RC3-013 aggregate 为 `passed`、61 checks、123 fail-closed negative cases；这些 counts 已被后续 current summary superseded。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：新增 `scripts/complete-rc3-production-signature-verification-from-inbox.ps1`，把 external return inbox 到 completion runner 的最后一步固化为 wrapper：它先运行 inbox audit，只允许总共正好 1 个 eligible `signature_values` 或 `signature_bundle` return candidate，然后委托现有 `scripts/complete-rc3-production-signature-verification.ps1`；默认空 inbox 结果 `.workflow/artifacts/rc3-production-signature-verification/external-return-inbox-completion/result.json` 为 `blocked`，`completion_invoked=false`，blocker 为 `inbox_completion.single_candidate_required`。新增 `scripts/verify-rc3-external-return-inbox-completion-wrapper-fail-closed-fixtures.ps1`，覆盖 empty inbox、mixed values + bundle、unsupported schema、values candidate crypto-blocked、bundle candidate crypto-blocked 5 个负向 case，聚合结果 `.workflow/artifacts/rc3-production-signature-verification/external-return-inbox-completion-wrapper-negatives/result.json` 当时为 `passed`、5/5 cases、2 个 completion-invoked crypto-blocked cases、3 个 pre-completion blocked cases。`scripts/audit-rc3-012-completion-gate.ps1` 和 `scripts/verify-rc3-production-signing-fail-closed.ps1` 已接入 wrapper evidence；该历史 checkpoint 的 RC3-012 gate 为 `passed`、176 checks、128 fail-closed negative cases，RC3-013 aggregate 为 `passed`、70 checks、128 fail-closed negative cases，后续已被 current summary superseded。`RC3-012` 仍不能标记完成。
- `RC3-012` 继续推进：把真实 local signature boundary probe 生成的 41-signature bundle 转换成 `agentos.rc3-external-signature-values.v1` 负例后，signature values preflight / completion / receipt / inbound package 全部 fail closed，分别为 12/12、19/19、13/13、5/5 cases；本地签名值会以 `signature_values.external_boundary`、`signature_values.no_local_private_material` 和 `signature_values.not_local_fixture` 阻断，不能作为 production external signature return。
- `RC3-013` 历史聚合 checkpoint：只读聚合 verifier `scripts/verify-rc3-production-signing-fail-closed.ps1` 已接入既有 RC3-012 signature values / bundle / receipt / inbound / outbound package / exchange freshness 负向夹具、external return inbox 23 个负向候选、candidate-readiness readiness-only evidence、completion-candidate crypto-block evidence、from-inbox completion wrapper 5 个 fail-closed 负向 case、completion runner required input / input exclusivity / mode exclusivity evidence、direct returned signature values input-path negative cases、direct returned signature bundle input-path negative cases、local signature external-boundary negative、local bundle inbound negative、local bundle receipt negative、local bundle transformed-to-signature-values negative、public keyring verification、active evidence hash parity 和 semantic consistency，生成 `.workflow/artifacts/rc3-production-signing-fail-closed/result.json`。该历史 checkpoint 的聚合结果为 `passed`、70 checks、0 blockers、128 个 fail-closed negative cases、130/130 active evidence deliverable hashes matching；这些 aggregate counts 已被后续 `70/153` current summary superseded。结果仍写明 `raw_signature_values_archived=false`、`production_signature_verification_ready=false`、`rc3_012_complete=false`、`rc3_012_may_advance=false`、aggregate 本身不执行 signing / production crypto verification、不读取 local private material、不声明 production-ready。`RC3-012` 仍不能标记完成。
- `RC3-020` 历史预发布条件 checkpoint：只读 audit `scripts/audit-rc3-release-channel-publication-preconditions.ps1` 生成 `.workflow/artifacts/rc3-release-channel-publication-preconditions/result.json`（schema `agentos.rc3-release-channel-publication-preconditions.v1`，status `blocked`，当时为 42 checks，2 blockers）。该 audit 证明 release provenance promotable、release channel metadata 已 hash-bound provenance 且 immutable / append-only / content-addressed、candidate promotion passed、current release reproducibility passed（75 matched、0 divergent）、RC2 true block release gate passed、external signing export secret-safe、signature bundle intake 仍为 custody-only、production keyring / revocation not-revoked、rollback drill no-mutation 均成立；该历史 checkpoint 当时绑定 `RC3-012` completion gate（176 checks / 128 fail-closed negative cases）和 `RC3-013` production signing fail-closed aggregate（70 checks / 128 fail-closed negative cases），并覆盖 12/12 publication precondition negative cases。后续已被当前 `43 checks / 14 negatives / 185/153 / 70/153` downstream summary superseded。audit 和 fixtures 均不写真实 publication manifest、不写真实 channel index、不执行 signing / production crypto verification、不读取 local private material、不声明 production-ready，也不把 `RC3-020` 标记 completed。
- `RC3-021` consumer smoke 前置条件已固化为 blocked evidence：新增只读 audit `scripts/audit-rc3-signed-channel-consumer-preconditions.ps1`，生成 `.workflow/artifacts/rc3-signed-channel-consumer-preconditions/result.json`（schema `agentos.rc3-signed-channel-consumer-preconditions.v1`，status `blocked`，22 checks，9 blockers）。该 audit 证明 signed channel consumer smoke 在 `RC3-020` publication manifest / channel index 缺失、publication preconditions 仍 blocked、production completion 仍 blocked、production verification 仍有 41 个 `crypto_verified` blockers 时必须保持 blocked；同时确认 RC2 true block release gate passed、rollback drill no-mutation evidence passed、publication precondition negatives passed，并确认 target consumer smoke path 未预先存在。新增 `scripts/verify-rc3-signed-channel-consumer-preconditions-fail-closed-fixtures.ps1`，覆盖 13 个 consumer precondition 负向 case：plan 过早推进、publication precondition negatives failed、publication preconditions 误称 ready、publication manifest / channel index invalid schema 或 mutable / GA claim、production completion not ready、production verification crypto blocked、RC2 true block projection fallback、rollback drill active mutation、release channel metadata missing，以及 target consumer smoke preexist；聚合结果 `passed`、13/13 cases passed、fixture target files isolated。audit 和 fixtures 均不执行 consumer smoke、不写 publication manifest、不写 channel index、不执行 activation / rollback / remote dispatch / TUI authority、不执行 signing / production crypto verification、不读取 local private material、不声明 production-ready，也不把 `RC3-021` 标记 completed；blocked evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-021-signed-channel-consumer-preconditions-blocked.json`。
- `RC3-022` published-release support/recovery 前置条件已固化为 blocked evidence：新增只读 audit `scripts/audit-rc3-published-release-support-recovery-preconditions.ps1`，生成 `.workflow/artifacts/rc3-published-release-support-recovery-preconditions/result.json`（schema `agentos.rc3-published-release-support-recovery-preconditions.v1`，status `blocked`，20 checks，6 blockers）。该 audit 证明 published-release support bundle / recovery projection 在 `RC3-020` publication metadata 缺失、`RC3-021` consumer preconditions blocked、production completion blocked、production verification 仍有 41 个 `crypto_verified` blockers 时必须保持 blocked；同时确认 RC2 true block support/recovery baseline、rollback drill、support upload replay 和 incident recovery evidence 均已通过且保持 local / redacted / no-model-replay / no remote or TUI authority / no active mutation。audit 不写 published-release support bundle、recovery projection 或 support index，不执行 publication / consumer smoke / signing / production crypto verification / remote upload / activation / rollback，也不把 `RC3-022` 标记 completed；blocked evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-022-published-release-support-recovery-preconditions-blocked.json`。
- `RC3-022` fail-closed negative fixtures 已补充：新增 `scripts/verify-rc3-published-release-support-recovery-preconditions-fail-closed-fixtures.ps1`，聚合结果 `.workflow/artifacts/rc3-published-release-support-recovery-preconditions-negatives/result.json` 为 `passed`，9/9 cases passed、0 failed，覆盖 plan 过早推进、RC2 true block projection fallback、support/recovery 未脱敏、rollback drill active mutation、remote upload / model replay authority 以及目标 support bundle / recovery projection / support index preexist。fixture target files isolated，且不写真实 support bundle / recovery projection / support index，不执行 signing / production crypto verification / activation / rollback，也不推进 `RC3-012` 或完成 `RC3-022`。
- `RC3-023` production signing/publication gate 前置条件已固化为 blocked evidence：新增只读 audit `scripts/audit-rc3-production-signing-publication-gate-preconditions.ps1`，生成 `.workflow/artifacts/rc3-production-signing-publication-gate-preconditions/result.json`（schema `agentos.rc3-production-signing-publication-gate-preconditions.v1`，status `blocked`，25 checks，8 blockers）。该 audit 证明 signing/publication gate integration 在 RC3-012 production signature completion / crypto verification blocked、RC3-020 publication preconditions not ready、RC3-021 consumer preconditions not ready、RC3-022 support/recovery preconditions not ready、publication manifest / channel index absent 时必须保持 blocked；同时确认 base release provenance、release channel metadata、candidate promotion、reproducibility、RC2 true block release gate、rollback drill 和 RC3-013 fail-closed aggregate evidence 已存在。audit 不更新 provenance、不写 `rc3-production-signing-publication-gate.json`、不发布或消费 release channel、不执行 signing / production crypto verification、不写 support/recovery artifacts，也不把 `RC3-023` 标记 completed；blocked evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-023-production-signing-publication-gate-preconditions-blocked.json`。
- `RC3-023` fail-closed negative fixtures 已补充：新增 `scripts/verify-rc3-production-signing-publication-gate-preconditions-fail-closed-fixtures.ps1`，聚合结果 `.workflow/artifacts/rc3-production-signing-publication-gate-preconditions-negatives/result.json` 为 `passed`，12/12 cases passed、0 failed，覆盖 plan 过早推进、provenance blocked / GA claim、release channel metadata mutable、candidate promotion blocked、reproducibility divergent、completion gate not ready、production signing aggregate 越权执行 signing、support/recovery preconditions 误称 ready、RC2 true block projection fallback、rollback drill active mutation 和目标 gate preexist。fixture target files isolated，且不写 gate artifact / provenance update / publication manifest / channel index，不执行 signing / production crypto verification / consumer smoke / support recovery，也不推进 `RC3-012` 或完成 `RC3-023`。
- `RC3-030` final closeout 前置条件已固化为 blocked evidence：新增只读 audit `scripts/audit-rc3-final-closeout-preconditions.ps1`，生成 `.workflow/artifacts/rc3-final-closeout-preconditions/result.json`（schema `agentos.rc3-final-closeout-preconditions.v1`，status `blocked`，23 checks，11 blockers）。该 audit 证明 RC3 final audit / next milestone planning 在 RC3-012 production completion / crypto verification blocked、RC3-020 publication、RC3-021 consumer smoke、RC3-022 support/recovery、RC3-023 signing/publication gate integration 未完成、publication manifest / channel index / signing-publication gate artifact 缺失时必须保持 blocked。新增 `scripts/verify-rc3-final-closeout-preconditions-fail-closed-fixtures.ps1`，覆盖 14 个 closeout 负向 case：plan 过早推进、publication wave 仍 planned、production completion / verification / completion gate not ready、publication / consumer / support / gate preconditions not ready、publication manifest / channel index / gate artifact missing，以及 final audit / closeout summary target preexist；聚合结果 `passed`、14/14 cases passed、fixture target files isolated。audit 和 fixtures 均不写 final audit、不写 closeout summary、不发布或消费 release channel、不执行 signing / production crypto verification、不更新 provenance，也不推进 `RC3-012` 或完成 `RC3-030`；blocked evidence 已写入 `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-030-final-closeout-preconditions-blocked.json`。
- 下一步继续 `RC3-012`：接入真实 external production signature values 或 returned bundle 后重跑 receipt / assembly / intake / cryptographic production signature verification，直到 41 个 required artifacts（含 9 个 RC2 true block-device artifacts）全部通过。

## Production Distro RC1：installable image and first boot

目标：把 RC0 的 local release-candidate proof 推进为可安装、可首次启动、可恢复的 AIOS Linux Distro。RC1 不扩大为 GA production-ready claim；它要证明 candidate artifact 可以被安装到磁盘镜像，首次启动生成本地 identity / state / audit baseline，并且 upgrade / rollback / support evidence 仍然沿用 AgentCore + SecurityExecutionEngine 权威链路。

边界：

```text
RC0 proves local release-candidate gates.
RC1 must prove installable distro media and first-boot provisioning.
Installer stages artifacts; AgentCore and SecurityExecutionEngine still own activation.
TUI remains projection-controller only.
```

关键产物：

- Workflow session: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/workflow-session.json`
- RC1 plan: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/plan.json`
- RC1 install / first-boot contract: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/docs/installable-image-first-boot-contract.md`
- RC1 disk layout / state policy: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/docs/installed-disk-layout-and-state-policy.md`
- RC1 first-boot identity / audit / recovery schema: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/docs/first-boot-identity-audit-recovery-schema.md`
- RC1 installer threat model: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/docs/installer-threat-model.md`
- RC1-001 evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-001-installable-image-first-boot-contract.json`
- RC1-002 evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-002-installed-disk-layout-policy.json`
- RC1-003 evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-003-first-boot-identity-audit-recovery-schema.json`
- RC1-004 evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-004-installer-threat-model.json`
- RC1 installable media manifest: `.workflow/artifacts/rc1-installable-media/installable-media-manifest.json`
- RC1 installable media result: `.workflow/artifacts/rc1-installable-media/result.json`
- RC1-010 evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-010-installable-media-manifest.json`
- RC1 installed disk layout: `.workflow/artifacts/rc1-installed-disk/installed-disk-layout.json`
- RC1 installed disk assembly result: `.workflow/artifacts/rc1-installed-disk/result.json`
- RC1-011 evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-011-installed-disk-assembly.json`
- RC1 first-boot replay result: `.workflow/artifacts/rc1-first-boot/result.json`
- RC1-012 evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-012-first-boot-provisioning-replay.json`
- RC1 installer fail-closed result: `.workflow/artifacts/rc1-installer-fail-closed/result.json`
- RC1-013 evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-013-installer-fail-closed-fixtures.json`
- RC1 installed-system QEMU smoke result: `.workflow/artifacts/rc1-installed-system-smoke/result.json`
- RC1 installed-system marker manifest: `.workflow/artifacts/rc1-installed-system-smoke/first-boot-marker-manifest.json`
- RC1-020 evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-020-installed-system-qemu-smoke.json`
- RC1 installed support/recovery projection result: `.workflow/artifacts/rc1-installed-support-recovery/result.json`
- RC1 installed support bundle: `.workflow/artifacts/rc1-installed-support-recovery/support-bundle-redacted.json`
- RC1 installed recovery projection: `.workflow/artifacts/rc1-installed-support-recovery/recovery-projection.json`
- RC1-021 evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-021-installed-support-recovery-projection.json`
- RC1 installed rollback drill result: `.workflow/artifacts/rc1-installed-rollback-drill/result.json`
- RC1-022 evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-022-installed-rollback-drill.json`
- RC1 installed-system release gate: `.workflow/artifacts/release/rc1-installed-system-gate.json`
- RC1 release provenance: `.workflow/artifacts/release/provenance.json`
- RC1 candidate promotion result: `.workflow/artifacts/candidate-promotion/default-result.json`
- RC1 release reproducibility result: `.workflow/artifacts/release-reproducibility-fast/result.json`
- RC1 production signing request: `.workflow/artifacts/production-signing/rc1-023-signing-request.json`
- RC1-023 evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/RC1-023-release-provenance-promotion-gate.json`
- RC1 final audit evidence: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/FINAL-AUDIT-20260531-production-distro-rc1.json`
- RC1 final closeout summary: `.workflow/active/WFS-20260530-agentos-production-distro-rc1/docs/final-rc1-closeout-summary.md`
- RC2 workflow plan: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/plan.json`
- RC2 workflow session: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/workflow-session.json`

### RC1 Wave 0：install contract and media model

- `RC1-001`：定义 installable distro image and first-boot provisioning contract（completed）
- `RC1-002`：定义 disk layout、A/B slots、EFI/BIOS boot metadata and persistent state mount policy（completed）
- `RC1-003`：定义 first-boot local identity、audit seal and recovery baseline schema（completed）
- `RC1-004`：定义 installer threat model：no shell bypass、no secret material in media、no activation during copy（completed）

退出标准：

- 安装介质 contract 明确区分 copy/stage 与 activate。
- first boot 可以生成 local node identity、RunStore、AuditJournal、rollback baseline。
- 安装器不获得 AgentCore / SecurityExecutionEngine 之外的 side-effect authority。

### RC1 Wave 1：image assembly and installer replay

- `RC1-010`：实现 installable image manifest and deterministic media metadata（completed）
- `RC1-011`：实现 local disk image assembly path with rootfs/runtime artifacts（completed）
- `RC1-012`：实现 first-boot provisioning replay with local identity and audit seal（completed）
- `RC1-013`：实现 installer fail-closed fixtures for corrupted media、missing signature、slot mismatch、secret leak（completed）

退出标准：

- install image manifest 绑定 release provenance、rootfs runtime manifest、production public trust store 和 RC0 decision evidence。
- first-boot replay 不需要网络或 external LLM。
- corrupted / unsigned / slot-inconsistent media fail closed before activation。

### RC1 Wave 2：installed-system verification

- `RC1-020`：增加 installed-system QEMU boot smoke with first-boot markers（completed）
- `RC1-021`：增加 installed-system support bundle and recovery evidence projection（completed）
- `RC1-022`：增加 installed-system update rollback drill from inactive slot（completed）
- `RC1-023`：把 install replay、first boot、installed QEMU smoke 接入 release provenance / promotion gate（completed）

退出标准：

- projection-backed installed-system QEMU smoke 观察到 handoff、runtime artifact、TUI console、first-boot provisioning 和 audit seal markers；true block disk boot 仍是后续任务。
- installed support bundle 能解释 install provenance、local identity、slot state 和 rollback baseline。
- promotion gate 在 install replay / installed QEMU smoke skipped 或 failed 时阻塞。

### RC1 Wave 3：RC1 closeout

- `RC1-030`：运行 Production Distro RC1 final audit and next milestone planning（completed）

退出标准：

- `scripts/build-release.ps1` 或后续 release gate 能同时证明 RC0 release candidate evidence 和 RC1 installable first-boot evidence。
- candidate promotion、reproducibility、production signing intake 都包含 install / first-boot decision evidence。
- 下一 milestone 根据审计缺口进入 true block-device boot、bootable raw disk image、installer disk-write UX 和 RC2 release gate。
- RC1 final audit 已完成：`.workflow/active/WFS-20260530-agentos-production-distro-rc1/evidence/FINAL-AUDIT-20260531-production-distro-rc1.json`。
- 当前 promotion decision：`rc1-closeout-pass-next-milestone-planning`；这不是 GA production-ready claim，true block-device boot、外部 production signing ceremony、multi-node fleet rings、hosted remote registry transport 和 GA hardening 仍是后续 milestone。

## Production Distro RC2：true block-device boot and installer execution proof

目标：把 RC1 的 projection-backed installed-system smoke 推进为真实 attached block-device boot proof。RC2 必须生成可审计的 bootable disk image、通过 QEMU 从 block device 启动、证明 bootloader / kernel / initramfs / first boot handoff 和 persistent state mount truth，同时保持 RC1 的 authority boundary：copy/stage 不是 activation，所有 side effects 仍由 AgentCore PlanSpec + SecurityExecutionEngine 仲裁，TUI 仍然只做 projection。

边界：

- 不接受 `projection-backed-initramfs-smoke` 作为 RC2 true boot 通过条件。
- 不宣称 GA production-ready。
- 不要求 first boot 访问网络、external LLM、remote fleet service 或 hosted registry。
- 不把 private signing material、raw enrollment token、raw secret 或 operator credential 放进 install media / disk image。
- 不开放 normal-mode arbitrary shell。
- 不允许 installer copy/stage 过程直接 mutation active slot、active artifact set 或 production ring。

关键 workflow：

- RC2 workflow: `.workflow/active/WFS-20260531-agentos-production-distro-rc2`
- RC2 plan: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/plan.json`
- RC2 session: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/workflow-session.json`
- RC2-001 true block-device boot contract: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/docs/true-block-device-boot-contract.md`
- RC2-001 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-001-true-block-device-boot-contract.json`
- RC2-002 installer UX / disk write / offline recovery contract: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/docs/installer-ux-disk-write-recovery-contract.md`
- RC2-002 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-002-installer-ux-disk-write-recovery-contract.json`
- RC2-003 persistent state mount truth / boot recovery boundary: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/docs/persistent-state-boot-recovery-boundary.md`
- RC2-003 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-003-persistent-state-boot-recovery-boundary.json`
- RC2-004 block-device installer threat model: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/docs/block-device-installer-threat-model.md`
- RC2-004 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-004-block-device-installer-threat-model.json`
- RC2-010 bootable disk assembly script: `scripts/assemble-rc2-bootable-disk-image.ps1`
- RC2-010 bootable disk manifest: `.workflow/artifacts/rc2-bootable-disk/bootable-disk-manifest.json`
- RC2-010 bootable disk assembly result: `.workflow/artifacts/rc2-bootable-disk/result.json`
- RC2-010 raw disk image: `.workflow/artifacts/rc2-bootable-disk/agentos-rc2.raw`
- RC2-010 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-010-bootable-disk-assembly.json`
- RC2-011 installer replay script: `scripts/rc2-installer-replay.ps1`
- RC2-011 installer replay result: `.workflow/artifacts/rc2-installer-replay/result.json`
- RC2-011 disk write plan: `.workflow/artifacts/rc2-installer-replay/disk-write-plan.json`
- RC2-011 disk write result: `.workflow/artifacts/rc2-installer-replay/disk-write-result.json`
- RC2-011 offline recovery packet: `.workflow/artifacts/rc2-installer-replay/offline-recovery-packet.json`
- RC2-011 target raw disk image: `.workflow/artifacts/rc2-installer-replay/target-agentos-rc2.raw`
- RC2-011 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-011-installer-replay-exact-consent.json`
- RC2-012 fail-closed fixture script: `scripts/rc2-block-boot-fail-closed-fixtures.ps1`
- RC2-012 fail-closed fixture result: `.workflow/artifacts/rc2-block-boot-fail-closed/result.json`
- RC2-012 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-012-true-boot-installer-fail-closed-fixtures.json`
- RC2-020 true block boot smoke script: `scripts/rc2-true-block-boot-smoke.ps1`
- RC2-020 true block boot result: `.workflow/artifacts/rc2-true-block-boot/result.json`
- RC2-020 QEMU serial log: `.workflow/artifacts/rc2-true-block-boot/qemu-serial.log`
- RC2-020 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-020-true-block-device-boot-smoke.json`
- RC2-021 block support/recovery script: `scripts/rc2-block-support-recovery-projection.ps1`
- RC2-021 block support/recovery result: `.workflow/artifacts/rc2-block-support-recovery/result.json`
- RC2-021 persistent state mount truth: `.workflow/artifacts/rc2-block-support-recovery/persistent-state-mount-truth.json`
- RC2-021 first-boot disk seal: `.workflow/artifacts/rc2-block-support-recovery/first-boot-disk-seal.json`
- RC2-021 boot recovery boundary: `.workflow/artifacts/rc2-block-support-recovery/boot-recovery-boundary.json`
- RC2-021 support bundle redacted: `.workflow/artifacts/rc2-block-support-recovery/support-bundle-redacted.json`
- RC2-021 recovery projection: `.workflow/artifacts/rc2-block-support-recovery/recovery-projection.json`
- RC2-021 support index: `.workflow/artifacts/rc2-block-support-recovery/support-index.json`
- RC2-021 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-021-block-support-recovery-projection.json`
- RC2-022 block rollback drill script: `scripts/rc2-block-rollback-drill.ps1`
- RC2-022 block rollback drill result: `.workflow/artifacts/rc2-block-rollback-drill/result.json`
- RC2-022 inactive-slot update plan: `.workflow/artifacts/rc2-block-rollback-drill/inactive-slot-update-plan.json`
- RC2-022 inactive-slot staged candidate: `.workflow/artifacts/rc2-block-rollback-drill/inactive-slot-staged-candidate.json`
- RC2-022 candidate health report: `.workflow/artifacts/rc2-block-rollback-drill/candidate-health-report.json`
- RC2-022 rollback report: `.workflow/artifacts/rc2-block-rollback-drill/rollback-report.json`
- RC2-022 rollback index: `.workflow/artifacts/rc2-block-rollback-drill/rollback-index.json`
- RC2-022 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-022-block-rollback-drill.json`
- RC2-023 true block release gate script: `scripts/verify-rc2-true-block-release-gate.ps1`
- RC2-023 true block release gate: `.workflow/artifacts/release/rc2-true-block-release-gate.json`
- RC2-023 release provenance: `.workflow/artifacts/release/provenance.json`
- RC2-023 candidate promotion result: `.workflow/artifacts/candidate-promotion/default-result.json`
- RC2-023 production signing request: `.workflow/artifacts/production-signing/rc2-023-signing-request.json`
- RC2-023 release reproducibility result: `.workflow/artifacts/release-reproducibility-fast/result.json`
- RC2-023 skip-gate negative provenance: `.workflow/artifacts/rc2-023-skip-gate-negative/release/provenance.json`
- RC2-023 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/RC2-023-release-provenance-promotion-gate.json`
- RC2-030 final audit: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/evidence/FINAL-AUDIT-20260531-production-distro-rc2.json`
- RC2-030 closeout summary: `.workflow/active/WFS-20260531-agentos-production-distro-rc2/docs/final-rc2-closeout-summary.md`

### RC2 Wave 0：true boot contract and installer boundary

- `RC2-001`：定义 true block-device boot proof contract and bootloader handoff boundary（completed）
- `RC2-002`：定义 installer UX、disk write and offline recovery contract（completed）
- `RC2-003`：定义 persistent state mount truth and boot recovery boundary（completed）
- `RC2-004`：定义 block-device installer threat model（completed）

退出标准：

- contract 明确 raw disk image、partition map、bootloader handoff、kernel/initramfs authority、block device attachment、boot metadata 和 persistent state mount truth。
- installer UX contract 明确 copy/stage/activate 分离和 exact operator consent。
- threat model 覆盖 partition tamper、bootloader bypass、signature/revocation failure、state inside rootfs、secret leak、shell bypass、remote dispatch attempt 和 TUI mutation attempt。

### RC2 Wave 1：bootable disk assembly and installer replay

- `RC2-010`：实现 deterministic bootable disk image assembly with partition map and boot metadata（completed）
- `RC2-011`：实现 installer replay from install media to bootable disk image with exact consent（completed）
- `RC2-012`：实现 true boot and installer fail-closed fixtures（completed）

退出标准：

- bootable disk artifact hash-bound 且 metadata 可由 release provenance 消费。
- installer replay 只在 exact consent 后写入 / stage 到 disk image，不把 copy/stage 视为 activation。
- fail-closed fixtures 在 effect prepared 前阻断 partition / boot / signature / state / secret / shell / remote / TUI 攻击路径。

### RC2 Wave 2：true block boot verification

- `RC2-020`：增加 QEMU true block-device boot smoke with attached disk image（completed）
- `RC2-021`：增加 installed block-device support bundle and recovery projection（completed）
- `RC2-022`：增加 block-device inactive-slot update rollback drill（completed）
- `RC2-023`：把 true block-device boot evidence 接入 release provenance / promotion gate（completed）

退出标准：

- QEMU 通过 attached disk image 启动，不能只靠 projected initramfs smoke。
- support/recovery projection 能解释真实 block boot provenance、local identity、slot state、state mount 和 rollback baseline。
- promotion gate 在 true block-device boot missing / skipped / projected-only / failed 时阻塞。

### RC2 Wave 3：RC2 closeout

- `RC2-030`：运行 Production Distro RC2 final audit and next milestone planning（completed）

退出标准：

- release provenance、candidate promotion、reproducibility 和 signing request 都包含 true block-device boot decision evidence。
- RC2 final audit 明确 true block boot 的证明范围、仍未覆盖的 GA gap 和下一 milestone。

## Production Distro RC3：external production signing and release channel publication proof

目标：把 RC2 的 `ready-for-external-signer` 状态推进为可审计的 external production signing ceremony 和 release channel publication proof。RC3 必须证明 true-block-boot release candidate 可以导出给外部 production signer、接收 hash-bound production signature bundle、验证 public key custody / rotation / revocation、发布 immutable release channel，并在缺失签名、候选签名冒充、revoked key、channel tamper 或 rollback evidence 缺失时 fail closed。RC3 仍不宣称 GA production-ready。

边界：

- 不使用、不读取、不打包 `.local-release-authority/private/*.pem` 作为 RC3 acceptance。
- candidate hash-bound signature 不能满足 production signature gate。
- baseline verification 不要求 hosted network service、external LLM 或 remote control plane。
- release publication 不直接 mutate active slot、active artifact set、production ring 或 remote registry。
- TUI 仍是 projection-controller，不拥有 signing、publication、rollback 或 revocation authority。

关键 workflow：

- RC3 active workflow: `.workflow/active/WFS-20260531-agentos-production-distro-rc3`
- RC3 plan: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/plan.json`
- RC3 session: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/workflow-session.json`
- RC3 signing/publication contract: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/docs/external-production-signing-publication-contract.md`
- RC3-001 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-001-external-production-signing-publication-contract.json`
- RC3 signature bundle custody/revocation boundary: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/docs/signature-bundle-custody-revocation-boundary.md`
- RC3-002 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-002-signature-bundle-custody-revocation-boundary.json`
- RC3 release channel publication/rollback boundary: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/docs/release-channel-publication-rollback-boundary.md`
- RC3-003 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-003-release-channel-publication-rollback-boundary.json`
- RC3 signing/publication threat model: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/docs/production-signing-publication-threat-model.md`
- RC3-004 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-004-production-signing-publication-threat-model.json`
- RC3 external signing export script: `scripts/export-external-production-signing-request.ps1`
- RC3 external signing export result: `.workflow/artifacts/rc3-external-signing-request/result.json`
- RC3 external signing request: `.workflow/artifacts/rc3-external-signing-request/signing-request.json`
- RC3 external signing export manifest: `.workflow/artifacts/rc3-external-signing-request/export-manifest.json`
- RC3 external signing redaction report: `.workflow/artifacts/rc3-external-signing-request/redaction-report.json`
- RC3-010 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-010-external-signing-request-export.json`
- RC3 signature bundle intake script: `scripts/intake-external-production-signature-bundle.ps1`
- RC3 signature bundle intake result: `.workflow/artifacts/rc3-signature-bundle-intake/result.json`
- RC3 signature bundle intake request: `.workflow/artifacts/rc3-signature-bundle-intake/signing-request-intake.json`
- RC3 structural external signature bundle fixture: `.workflow/artifacts/rc3-signature-bundle-intake/signature-bundle-external-structural-fixture.json`
- RC3 signature bundle verification: `.workflow/artifacts/rc3-signature-bundle-intake/signature-bundle-verification.json`
- RC3 signature bundle installation: `.workflow/artifacts/rc3-signature-bundle-intake/signature-bundle-installation.json`
- RC3-011 evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-011-signature-bundle-intake.json`
- RC3-012 production signature verification result: `.workflow/artifacts/rc3-production-signature-verification/result.json`（blocked pending real external cryptographic signatures）
- RC3-012 production signature verification completion runner: `scripts/complete-rc3-production-signature-verification.ps1`
- RC3-012 production signature verification completion result: `.workflow/artifacts/rc3-production-signature-verification/completion-result.json`（blocked pending real external cryptographic signatures）
- RC3-012 signature values placeholder completion negative: `.workflow/artifacts/rc3-production-signature-verification/signature-values-placeholder-negative/completion-result.json`（blocked at assembly）
- RC3-012 signature values template completion negative: `.workflow/artifacts/rc3-production-signature-verification/signature-values-template-negative/completion-result.json`（blocked at signature values preflight）
- RC3-012 external signature values preflight script: `scripts/verify-rc3-external-signature-values.ps1`
- RC3-012 signature values template preflight negative: `.workflow/artifacts/rc3-production-signature-verification/signature-values-template-preflight-negative/result.json`（blocked，41 placeholders）
- RC3-012 external signature values fail-closed fixtures script: `scripts/verify-rc3-external-signature-values-fail-closed-fixtures.ps1`
- RC3-012 external signature values preflight negatives: `.workflow/artifacts/rc3-production-signature-verification/signature-values-preflight-negatives/result.json`（passed，12/12 negative cases blocked at preflight）
- RC3-012 external signature values completion fail-closed fixtures script: `scripts/verify-rc3-external-signature-values-completion-fail-closed-fixtures.ps1`
- RC3-012 external signature values completion negatives: `.workflow/artifacts/rc3-production-signature-verification/signature-values-completion-negatives/result.json`（passed，19/19 negative cases blocked before downstream steps，含 12 个 preflight completion cases、3 个 direct input-path cases、1 个 missing input case、1 个 mutually-exclusive values/bundle input case 和 2 个 existing-staged mode exclusivity cases）
- RC3-012 external signature values crypto fail-closed fixtures script: `scripts/verify-rc3-external-signature-values-crypto-fail-closed-fixtures.ps1`
- RC3-012 external signature values crypto negative: `.workflow/artifacts/rc3-production-signature-verification/signature-values-crypto-negative/result.json`（passed，preflight / receipt / assembly / availability / intake pass，production crypto blocks 41/41）
- RC3-012 external signature values receipt script: `scripts/archive-rc3-external-signature-values-receipt.ps1`
- RC3-012 external signature values receipt: `.workflow/artifacts/rc3-production-signature-verification/external-signature-values-receipt/result.json`（passed，41 hash-only signature value entries，raw_signature_values_archived=false）
- RC3-012 external signature values receipt fail-closed fixtures script: `scripts/verify-rc3-external-signature-values-receipt-fail-closed-fixtures.ps1`
- RC3-012 external signature values receipt negatives: `.workflow/artifacts/rc3-production-signature-verification/signature-values-receipt-negatives/result.json`（passed，18/18 receipt negatives blocked，source_hash_negative_cases=5，raw_signature_value_fields=0）
- RC3-012 external signature values inbound verifier script: `scripts/verify-rc3-external-signature-values-inbound-package.ps1`
- RC3-012 external signature values inbound verification: `.workflow/artifacts/rc3-production-signature-verification/external-signature-values-inbound-verification/result.json`（passed，61 checks，41 returned values，hash-only receipt entries=41，production_signature_verification_ready=false）
- RC3-012 external signature values inbound fail-closed fixtures script: `scripts/verify-rc3-external-signature-values-inbound-fail-closed-fixtures.ps1`
- RC3-012 external signature values inbound negatives: `.workflow/artifacts/rc3-production-signature-verification/signature-values-inbound-negatives/result.json`（passed，11/11 inbound negatives blocked，raw_signature_value_fields=0）
- RC3-012 external signature bundle availability audit script: `scripts/audit-rc3-external-signature-bundles.ps1`
- RC3-012 external signature bundle availability audit: `.workflow/artifacts/rc3-production-signature-verification/signature-bundle-availability-audit.json`（blocked，0 eligible external bundles，含 rejection reason counts）
- RC3-012 external signature bundle fail-closed fixtures script: `scripts/verify-rc3-external-signature-bundle-fail-closed-fixtures.ps1`
- RC3-012 external signature bundle completion negatives: `.workflow/artifacts/rc3-production-signature-verification/signature-bundle-completion-negatives/result.json`（passed，11/11 negative cases blocked at availability audit with downstream steps skipped，`input_path_negative_cases=3`）
- RC3-012 external signature bundle crypto fail-closed fixtures script: `scripts/verify-rc3-external-signature-bundle-crypto-fail-closed-fixtures.ps1`
- RC3-012 external signature bundle crypto negative: `.workflow/artifacts/rc3-production-signature-verification/signature-bundle-crypto-negative/result.json`（passed，availability / receipt / intake pass，production crypto blocks 41/41）
- RC3-012 external signature bundle receipt script: `scripts/archive-rc3-external-signature-bundle-receipt.ps1`
- RC3-012 external signature bundle receipt: `.workflow/artifacts/rc3-production-signature-verification/external-signature-bundle-receipt/result.json`（passed，41 hash-only signature value entries，raw_signature_values_archived=false）
- RC3-012 external signature bundle receipt fail-closed fixtures script: `scripts/verify-rc3-external-signature-bundle-receipt-fail-closed-fixtures.ps1`
- RC3-012 external signature bundle receipt negatives: `.workflow/artifacts/rc3-production-signature-verification/signature-bundle-receipt-negatives/result.json`（passed，15/15 bundle receipt negatives blocked，source_hash_negative_cases=4，local signature boundary case reads the existing local boundary fixture without copying a full local signed bundle into receipt-negatives，raw_signature_value_fields=0）
- RC3-012 external signature bundle crypto negative receipt: `.workflow/artifacts/rc3-production-signature-verification/signature-bundle-crypto-negative/signature-bundle-receipt/result.json`（passed before intake）
- RC3-012 external signature bundle inbound verifier script: `scripts/verify-rc3-external-signature-bundle-inbound-package.ps1`
- RC3-012 external signature bundle inbound verification: `.workflow/artifacts/rc3-production-signature-verification/external-signature-bundle-inbound-verification/result.json`（passed，52 checks，41 returned bundle signatures，bundle verification ready-for-cryptographic-verification，production_signature_verification_ready=false）
- RC3-012 external signature bundle inbound fail-closed fixtures script: `scripts/verify-rc3-external-signature-bundle-inbound-fail-closed-fixtures.ps1`
- RC3-012 external signature bundle inbound negatives: `.workflow/artifacts/rc3-production-signature-verification/signature-bundle-inbound-negatives/result.json`（passed，5/5 bundle inbound negatives blocked，含 real local signature bundle boundary case，raw_bundle_signature_value_fields=0，result_raw_bundle_signature_value_fields=0）
- RC3-012 external signer outbound package script: `scripts/export-rc3-external-signer-outbound-package.ps1`
- RC3-012 external signer outbound package: `.workflow/artifacts/rc3-production-signature-verification/external-signer-outbound-package/result.json`（passed，48 package content files，6 outbound files，41 payload files，secret-safe）
- RC3-012 external signer outbound package verifier script: `scripts/verify-rc3-external-signer-outbound-package.ps1`
- RC3-012 external signer outbound package verification: `.workflow/artifacts/rc3-production-signature-verification/external-signer-outbound-package-verification/result.json`（passed，190 checks，48 actual files，content hash recomputed，package-internal bindings matched，read-boundary guards passed）
- RC3-012 external signer outbound package fail-closed fixtures script: `scripts/verify-rc3-external-signer-outbound-package-fail-closed-fixtures.ps1`
- RC3-012 external signer outbound package negatives: `.workflow/artifacts/rc3-production-signature-verification/external-signer-outbound-package-negatives/result.json`（passed，10/10 package tamper / secret / path / hash drift cases blocked）
- RC3-012 completion gate audit script: `scripts/audit-rc3-012-completion-gate.ps1`
- RC3-012 completion gate audit: `.workflow/artifacts/rc3-production-signature-verification/rc3-012-completion-gate-audit/result.json`（passed，106 checks，72 fail-closed negatives，rc3_012_complete=false，rc3_012_may_advance=false）
- RC3-012 external signer handoff inbound acceptance: `.workflow/artifacts/rc3-production-signature-verification/external-signer-handoff.json`（ready-for-external-signer，returned values / returned bundle inbound verifier commands and hash-only receipt commands present，custody-only，production_signature_verification_ready=false）
- RC3-012 external signer handoff package verification: `.workflow/artifacts/rc3-production-signature-verification/external-signer-handoff-package-verification.json`（passed，164 checks，6 outbound files，41 payloads，inbound acceptance commands verified，read-boundary guards passed）
- RC3-012 external signer outbound package verification: `.workflow/artifacts/rc3-production-signature-verification/external-signer-outbound-package-verification/result.json`（passed，190 checks，48 actual files，content hash `6da4bf92140304864dbd6d70195cc39e4090ba727e02c801caf9b2dbde1e2fa6`，packaged handoff inbound acceptance verified，read-boundary guards passed）
- RC3-012 completion gate audit: `.workflow/artifacts/rc3-production-signature-verification/rc3-012-completion-gate-audit/result.json`（passed，107 checks，72 fail-closed negatives，handoff inbound acceptance checks=7，rc3_012_complete=false，rc3_012_may_advance=false）
- RC3-012 external signer exchange freshness audit script: `scripts/audit-rc3-external-signer-exchange-freshness.ps1`
- RC3-012 external signer exchange freshness audit: `.workflow/artifacts/rc3-production-signature-verification/external-signer-exchange-freshness/result.json`（passed，40 checks，exchange_fresh=true，content hash `8a118aac78fa2a4500fbb4b855f45abb2f7ec059db5bd723fd1ed0b04b9f9686`）
- RC3-012 completion gate audit: `.workflow/artifacts/rc3-production-signature-verification/rc3-012-completion-gate-audit/result.json`（passed，114 checks，72 fail-closed negatives，exchange freshness checks=40，rc3_012_complete=false，rc3_012_may_advance=false）
- RC3-012 external signer exchange freshness fail-closed fixtures script: `scripts/verify-rc3-external-signer-exchange-freshness-fail-closed-fixtures.ps1`
- RC3-012 external signer exchange freshness negatives: `.workflow/artifacts/rc3-production-signature-verification/external-signer-exchange-freshness-negatives/result.json`（passed，10/10 stale / drift / blocked / sensitive-marker cases blocked，含 bundle inbound verification hash drift 对称用例）
- RC3-012 completion gate audit: `.workflow/artifacts/rc3-production-signature-verification/rc3-012-completion-gate-audit/result.json`（passed，119 checks，82 fail-closed negatives，exchange freshness negative cases=10，rc3_012_complete=false，rc3_012_may_advance=false）
- RC3-012 external signer secret safety audit script: `scripts/audit-rc3-external-signer-secret-safety.ps1`
- RC3-012 external signer secret safety audit: `.workflow/artifacts/rc3-production-signature-verification/external-signer-secret-safety/result.json`（passed，25 checks，64 files scanned，48 outbound package files scanned，forbidden_marker_hits=0，raw_signature_value_field_hits=0，rc3_012_complete=false，rc3_012_may_advance=false）
- RC3-012 completion gate audit: `.workflow/artifacts/rc3-production-signature-verification/rc3-012-completion-gate-audit/result.json`（passed，125 checks，81 fail-closed negatives，secret safety checks=25，secret marker/raw signature field hits=0，rc3_012_complete=false，rc3_012_may_advance=false）
- RC3-012 external return readiness audit script: `scripts/audit-rc3-external-return-readiness.ps1`
- RC3-012 external return readiness audit: `.workflow/artifacts/rc3-production-signature-verification/external-return-readiness/result.json`（passed，42 checks，external_return_intake_ready=true，values_return_path_ready=true，bundle_return_path_ready=true，production_signature_verification_ready=false）
- RC3-012 external return inbox audit script: `scripts/audit-rc3-external-return-inbox.ps1`
- RC3-012 external return inbox audit: `.workflow/artifacts/rc3-production-signature-verification/external-return-inbox/result.json`（passed，23 checks，0 candidates，0 rejected candidates，0 reparse point candidates，0 ambiguous return candidates，completion_runner_candidate_ready=false）
- RC3-012 external return inbox candidate-readiness script: `scripts/verify-rc3-external-return-inbox-candidate-readiness.ps1`
- RC3-012 external return inbox candidate-readiness: `.workflow/artifacts/rc3-production-signature-verification/external-return-inbox-candidate-readiness/result.json`（passed，1 case，2 json candidates，1 values candidate，1 bundle candidate，child audit exit code required，completion_runner_candidate_ready=true，production_signature_verification_ready=false）
- RC3-012 external return inbox fail-closed fixtures script: `scripts/verify-rc3-external-return-inbox-fail-closed-fixtures.ps1`
- RC3-012 external return inbox negatives: `.workflow/artifacts/rc3-production-signature-verification/external-return-inbox-negatives/result.json`（passed，30/30 inbox negative candidates blocked，含 real local signature bundle return、hidden signature values/bundle JSON return files、same-type multiple eligible values/bundle return files、unsupported non-JSON inbox file、unsupported hidden non-JSON inbox file、unsupported ordinary directory、unsupported-reparse-point-directory、unsupported-reparse-point-inbox-root、outside-inbox-root-no-create、unsafe ArtifactDir / forbidden OutputPath / unsafe child input path policy probes，以及 invalid-json 和 unsupported-schema raw/sensitive hygiene，child audit exit code required，fixture input raw_signature_value_fields=329，fixture input raw_bundle_signature_value_fields=370，deliberate_sensitive_marker_cases=3，raw_signature_values_archived=false，outside drop directory not created）
- RC3-012 external return inbox completion-candidates fail-closed script: `scripts/verify-rc3-external-return-inbox-completion-candidates-fail-closed-fixtures.ps1`
- RC3-012 external return inbox completion-candidates: `.workflow/artifacts/rc3-production-signature-verification/external-return-inbox-completion-candidates/result.json`（passed，2/2 cases passed，2 completion-runner candidate-ready cases，2 production crypto-blocked cases，82 crypto_verified blockers，child audit exit 0 cases=2，blocked completion exit 1 cases=2，rc3_012_complete=false，rc3_012_may_advance=false）
- RC3-012 external return inbox completion wrapper script: `scripts/complete-rc3-production-signature-verification-from-inbox.ps1`
- RC3-012 external return inbox completion wrapper: `.workflow/artifacts/rc3-production-signature-verification/external-return-inbox-completion/result.json`（blocked，completion_invoked=false，eligible_return_candidates=0，blocker=`inbox_completion.single_candidate_required`，rc3_012_complete=false，rc3_012_may_advance=false）
- RC3-012 external return inbox completion wrapper fail-closed script: `scripts/verify-rc3-external-return-inbox-completion-wrapper-fail-closed-fixtures.ps1`
- RC3-012 external return inbox completion wrapper negatives: `.workflow/artifacts/rc3-production-signature-verification/external-return-inbox-completion-wrapper-negatives/result.json`（passed，7/7 cases，5 pre-completion blocked cases including selected-candidate hash drift / TOCTOU，2 completion-invoked crypto-blocked cases，2 blocked completion exit 1 cases，selected_candidate_hash_mismatch_cases=1，rc3_012_complete=false，rc3_012_may_advance=false）
- RC3-012 external return inbox fixture path-isolation hardening: `scripts/verify-rc3-external-return-inbox-fail-closed-fixtures.ps1`、`scripts/verify-rc3-external-return-inbox-completion-candidates-fail-closed-fixtures.ps1` 和 `scripts/verify-rc3-external-return-inbox-completion-wrapper-fail-closed-fixtures.ps1` now reject unexpected negative artifact roots, require `OutputPath` to be a strict child of the expected artifact root, require case reset/drop/candidate/shim writes to stay under each case root, reject fixture reparse points before recursive delete/write, and keep `outside-inbox-root-no-create` inside a case-local outside-expected-root probe instead of `.workflow/temp`. Reran all 3 harnesses, `RC3-012` gate, `RC3-013` aggregate, and downstream blocked preconditions; inbox negatives are now `30/30`, completion-candidates remain `2/2`, wrapper negatives remain `7/7`, active evidence parity is `passed` with 130/130 hashes, semantic consistency is `passed` with 34 checks, and `RC3-012` remains blocked pending real external production signatures.
- RC3-012 external signer outbound package negative fixture path-isolation hardening: `scripts/verify-rc3-external-signer-outbound-package-fail-closed-fixtures.ps1` now rejects unexpected negative artifact roots, requires `OutputPath` to be a strict child of `.workflow/artifacts/rc3-production-signature-verification/external-signer-outbound-package-negatives`, requires case directories/package roots/manifest-derived package paths to remain strict descendants, and rejects fixture reparse points before recursive delete/write. That checkpoint reran outbound package verification, outbound package negatives, exchange freshness audit/negatives, secret-safety audit, `RC3-012` gate, `RC3-013` aggregate, downstream blocked preconditions, and active evidence audits; outbound package verification was then `passed` with 186 checks, superseded by the current 190-check read-boundary summary. Outbound negatives remain `10/10`, exchange freshness negatives remain `10/10`, active evidence parity is `passed` with 130/130 hashes, semantic consistency is `passed` with 33 checks, and `RC3-012` remains blocked pending real external production signatures.
- RC3-012 external signer outbound package producer root/reparse hardening: `scripts/export-rc3-external-signer-outbound-package.ps1` now requires the exact expected artifact root `.workflow/artifacts/rc3-production-signature-verification/external-signer-outbound-package`, rejects `PackageDir == ArtifactDir`, requires package/manifest/result writes to remain strict descendants of the artifact root, rejects existing reparse points before package reset/write/copy, and refuses outbound source reads outside the repo or under `.local-release-authority/private`. Verified bad `ArtifactDir`, bad `PackageDir`, publication `ManifestPath`, and private `HandoffPath` probes all fail closed before producing release outputs; default export remains `passed` with 152 checks, outbound verification remains `passed` with 186 checks, outbound negatives remain `10/10`, exchange freshness negatives remain `10/10`, secret safety remains `passed`, `RC3-012` gate remains `185/153`, `RC3-013` aggregate remains `70/153`, downstream preconditions remain blocked/planned, active evidence parity is `passed` with 130/130 hashes, semantic consistency is `passed` with 33 checks, and `RC3-012` remains blocked pending real external production signatures.
- RC3-012 external signer outbound package verifier read-boundary hardening: `scripts/verify-rc3-external-signer-outbound-package.ps1` now validates verification artifact roots, requires `OutputPath` to remain a strict child of the verification artifact dir, rejects package result / manifest inputs outside the expected outbound package or negative fixture roots, rejects `.local-release-authority/private` and repo-external reads before file access, validates package root boundaries before traversal, skips manifest-derived `package_path` reads/scans until they are proven inside the package root, and records aggregate read-boundary blockers instead of touching escaped targets. Verified bad `ArtifactDir`, bad `OutputPath`, bad `PackageResultPath`, and private `PackageManifestPath` probes all fail closed before producing release outputs; outbound verification is now `passed` with 190 checks, outbound negatives remain `10/10`, exchange freshness negatives remain `10/10`, secret safety remains `passed`, `RC3-012` gate remains `185/153`, `RC3-013` aggregate remains `70/153`, downstream preconditions remain blocked/planned, active evidence parity is `passed` with 130/130 hashes, semantic consistency is `passed` with 33 checks, and `RC3-012` remains blocked pending real external production signatures.
- RC3-012 external signer handoff package verifier read-boundary hardening: `scripts/verify-rc3-external-signer-handoff-package.ps1` now requires the exact RC3 production-signature-verification artifact root, requires `OutputPath` to be a strict child of that root, restricts top-level handoff / signing request / payload pack inputs to allowed RC3 artifact roots, restricts verifier / receipt script path parameters to `scripts/`, rejects repo-external and `.local-release-authority/private` paths before access, and treats handoff `outbound_files[].path` plus payload pack `payload.path` boundary violations as blockers without reading, hashing, or scanning escaped targets. Verified bad `ArtifactDir`, bad `OutputPath`, bad `HandoffPath`, private `SigningRequestPath`, private `PayloadPackPath`, script path escape, derived outbound private path, and derived payload private path probes all fail closed; handoff package verification is now `passed` with 164 checks, exchange freshness remains `passed` with 40 checks, exchange freshness negatives remain `10/10`, secret safety remains `passed`, `RC3-012` gate remains `185/153`, `RC3-013` aggregate remains `70/153`, downstream preconditions remain blocked/planned, active evidence parity is `passed` with 130/130 hashes, semantic consistency is `passed` with 33 checks, and `RC3-012` remains blocked pending real external production signatures.
- RC3-012 external signature values inbound verifier read-boundary hardening: `scripts/verify-rc3-external-signature-values-inbound-package.ps1` now validates the expected verification artifact root, requires `ArtifactDir` and `OutputPath` plus child preflight/receipt outputs to stay within allowed RC3 artifact roots as strict descendants, restricts `PreflightScriptPath` and `ReceiptScriptPath` to fixed leaves under `scripts/`, rejects repo-external paths, `.local-release-authority/private` paths, and reparse points before reads/hashes/child invocation, and converts business input boundary failures into blocked results instead of touching forbidden/private targets. Verified bad `ArtifactDir`, bad `OutputPath`, private `SignatureValuesPath`, and wrong preflight script leaf probes all fail closed; values inbound verification is now `passed` with 61 checks, 41 signatures, 0 blockers, and no raw signature archival; values inbound negatives remain `11/11`; `RC3-012` gate remains `185/153`, `RC3-013` aggregate remains `70/153`, downstream preconditions remain blocked/planned, active evidence parity is `passed` with 130/130 hashes, semantic consistency is `passed` with 33 checks, and `RC3-012` remains blocked pending real external production signatures.
- RC3-012 external signature bundle inbound verifier read-boundary hardening: `scripts/verify-rc3-external-signature-bundle-inbound-package.ps1` now mirrors the values inbound verifier path policy for `ArtifactDir`, `OutputPath`, child availability/verification outputs, fixed child script leaves, `SignatureBundlePath`, `SigningRequestPath`, bundle template, outbound package inputs, repo-external paths, `.local-release-authority/private` paths, and reparse points before reads/hashes/child invocation; business input boundary failures become blocked results with child steps skipped instead of touching forbidden/private targets. Verified bad `ArtifactDir`, bad `OutputPath`, private `SignatureBundlePath`, wrong availability script leaf, wrong bundle verifier script leaf, and repo-external `SigningRequestPath` probes all fail closed; bundle inbound verification is now `passed` with 52 checks, 41 signatures, 0 blockers, and no raw bundle signature archival; bundle inbound negatives remain `5/5`; `RC3-012` gate remains `185/153`, `RC3-013` aggregate remains `70/153`, downstream preconditions remain blocked/planned, active evidence parity is `passed` with 130/130 hashes, semantic consistency is `passed` with 33 checks, and `RC3-012` remains blocked pending real external production signatures.
- RC3-012 external signature receipt archiver read/write-boundary hardening: `scripts/archive-rc3-external-signature-values-receipt.ps1` and `scripts/archive-rc3-external-signature-bundle-receipt.ps1` now require receipt `ArtifactDir` under `.workflow/artifacts/rc3-production-signature-verification`, require `OutputPath` and child preflight/availability outputs to remain strict descendants of the selected artifact dir, restrict child script paths to fixed leaves under `scripts/`, reject repo-external / `.local-release-authority/private` / reparse paths before reads or hashes, and convert business input path policy failures into blocked hash-only receipts with child invocation skipped. Verified 10 boundary probes covering bad `ArtifactDir`, bad `OutputPath`, private returned values/bundle sentinel paths, wrong child script leaf, and repo-external `SigningRequestPath`; sentinel files and outside output were not created. Values receipt is `passed` with 30 checks / 41 signatures, bundle receipt is `passed` with 31 checks / 41 signatures, receipt negatives remain values `18/18` and bundle `15/15`, inbound verifiers remain values `61 checks` / bundle `52 checks`, `RC3-012` gate remains `185/153`, `RC3-013` aggregate remains `70/153`, downstream preconditions remain blocked/planned, active evidence parity is `passed` with 130/130 hashes, semantic consistency is `passed` with 33 checks, and `RC3-012` remains blocked pending real external production signatures.
- RC3-012 external signature receipt negative harness path-isolation hardening: `scripts/verify-rc3-external-signature-values-receipt-fail-closed-fixtures.ps1` now requires the exact values receipt negative artifact root, strict-descendant `OutputPath`, guarded case directories/stale receipts/synthetic negatives/gate results, fixed receipt/gate script leaves, repo-local non-private input reads, and reparse-point rejection before fixture delete/write. `scripts/verify-rc3-external-signature-bundle-receipt-fail-closed-fixtures.ps1` now applies the same controls to bundle receipt negatives and no longer copies the full local signed bundle into `signature-bundle-receipt-negatives`; the local-boundary receipt case reads the existing local boundary fixture path after policy checks. Verified bad `ArtifactDir`, escaped `OutputPath`, wrong receipt script leaf, and `.local-release-authority/private` sentinel input probes fail closed with no escaped output. Values receipt negatives remain `18/18`, bundle receipt negatives remain `15/15`, bundle receipt local-boundary case directory contains only receipt/availability outputs, `RC3-012` gate remains `185/153`, `RC3-013` aggregate remains `70/153`, downstream preconditions remain blocked/planned, active evidence parity is `passed` with 130/130 hashes, semantic consistency is `passed` with 33 checks, and `RC3-012` remains blocked pending real external production signatures.
- RC3-012 local signature external-boundary negative script: `scripts/verify-rc3-local-signature-bundle-external-boundary-fail-closed.ps1`
- RC3-012 local signature external-boundary negative: `.workflow/artifacts/rc3-production-signature-verification/local-signature-boundary-negative/result.json`（passed，1/1 case passed，local signed bundle signatures=41，availability eligible bundles=0，rejection reasons=`not_external_boundary`/`local_fixture`，downstream receipt/intake/production verification skipped，rc3_012_complete=false，rc3_012_may_advance=false）
- RC3 active evidence hash parity audit: `.workflow/artifacts/rc3-active-evidence-hash-parity/result.json`（passed，7 active evidence files，130 deliverable hashes，mismatches=0，missing_files=0，missing_path_fields=0，rc3_012_complete=false，rc3_012_may_advance=false）
- RC3 active evidence semantic consistency audit: `.workflow/artifacts/rc3-active-evidence-semantic-consistency/result.json`（passed，34 checks，0 blockers，forbidden_output_paths_checked=14，forbidden_output_paths_present=0，stale_pattern_hits=0，self_reference_hits=0，authority_leakage_hits=0，private_marker_hits=0，parity deliverable hashes=130，rc3_012_complete=false，rc3_012_may_advance=false；不签名、不跑 production crypto、不推进 RC3-012）
- RC3-012 completion gate audit: `.workflow/artifacts/rc3-production-signature-verification/rc3-012-completion-gate-audit/result.json`（passed，185 checks，155 fail-closed negatives，active evidence hash parity deliverable hashes=130，mismatches=0，active evidence semantic consistency checks=34，stale_pattern_hits=0，self_reference_hits=0，authority_leakage_hits=0，private_marker_hits=0，local signature boundary negative cases=1，signature values preflight negatives=12，signature values completion negatives=19，signature values receipt negatives=18，signature values inbound negatives=11，signature values input_path_negative_cases=3，signature bundle completion negatives=11，signature bundle input_path_negative_cases=3，signature bundle receipt negatives=15，required_input_cases=1，input_exclusivity_cases=1，mode_exclusivity_cases=2，external signer exchange freshness negative cases=10，external return readiness checks=42，external return values negative cases=60，external return bundle negative cases=31，external return inbox checks=23，candidate-readiness cases=1，candidate-readiness json candidates=2，candidate-readiness child audit exit 0 cases=1，completion-candidate cases=2，completion-candidate crypto-blocked cases=2，completion-candidate child audit exit 0 cases=2，blocked completion exit 1 cases=2，completion wrapper status=blocked，completion wrapper invoked=false，completion wrapper negative cases=9，completion wrapper pre-completion blocked cases=7，completion wrapper selected-candidate hash mismatch cases=2，external return inbox negative cases=30，external return inbox fixture input raw fields=329/370，external return inbox negative child audit exit 0 cases=30，bundle receipt local signature boundary case=true，external_return_intake_ready=true，external_return_inbox_candidate_ready=false，candidate_readiness_completion_runner_candidate_ready=true，rc3_012_complete=false，rc3_012_may_advance=false）
- RC3-012 semantic consistency ASCII marker: `rc3_current_summary=parity_hashes_130;gate_checks_185;gate_negatives_155;aggregate_checks_70;aggregate_negatives_155`
- RC3-012 completion-path harness hardening: `scripts/verify-rc3-external-signature-values-completion-fail-closed-fixtures.ps1`、`scripts/verify-rc3-external-signature-values-crypto-fail-closed-fixtures.ps1` 和 `scripts/verify-rc3-external-signature-bundle-fail-closed-fixtures.ps1` now reset stale PowerShell `$LASTEXITCODE` before invoking the completion runner; reran all 3 harnesses, `RC3-012` gate, `RC3-013` aggregate, and downstream blocked preconditions. Gate remains `passed` with `rc3_012_complete=false` / `rc3_012_may_advance=false`; no real production signature claim was made.
- RC3-012 inbound custody harness hardening: `scripts/verify-rc3-external-signature-values-inbound-package.ps1`、`scripts/verify-rc3-external-signature-values-inbound-fail-closed-fixtures.ps1`、`scripts/verify-rc3-external-signature-bundle-inbound-package.ps1` 和 `scripts/verify-rc3-external-signature-bundle-inbound-fail-closed-fixtures.ps1` now reset stale PowerShell `$LASTEXITCODE` before child preflight/receipt/availability/verifier invocations; reran inbound verifiers, inbound negatives, gate, aggregate, and downstream blocked preconditions. `RC3-012` remains blocked pending real external production signatures.
- RC3-012 preflight/outbound/freshness harness hardening: `scripts/verify-rc3-external-signature-values-fail-closed-fixtures.ps1`、`scripts/verify-rc3-external-signer-outbound-package-fail-closed-fixtures.ps1` 和 `scripts/verify-rc3-external-signer-exchange-freshness-fail-closed-fixtures.ps1` now reset stale PowerShell `$LASTEXITCODE` before child preflight/package-verifier/freshness-audit invocations; reran the 3 negative harnesses, `RC3-012` gate, `RC3-013` aggregate, and downstream blocked preconditions. Later child audit exit-code, visible/hidden non-JSON inbox hardening, reparse point directory hardening, inbox root reparse point hardening, outside inbox root no-create hardening, unsupported ordinary directory hardening, same-type multiple return candidate hardening, mutually exclusive completion input hardening, and completion mode exclusivity hardening supersede this checkpoint; current gate status is tracked by the latest RC3-012 completion gate entry; no real production signature claim was made.
- RC3 downstream precondition harness hardening: `scripts/verify-rc3-release-channel-publication-preconditions-fail-closed-fixtures.ps1`、`scripts/verify-rc3-signed-channel-consumer-preconditions-fail-closed-fixtures.ps1`、`scripts/verify-rc3-published-release-support-recovery-preconditions-fail-closed-fixtures.ps1`、`scripts/verify-rc3-production-signing-publication-gate-preconditions-fail-closed-fixtures.ps1` 和 `scripts/verify-rc3-final-closeout-preconditions-fail-closed-fixtures.ps1` now reset stale PowerShell `$LASTEXITCODE` before child precondition audit invocations; reran downstream negative harnesses and blocked audits through `RC3-030`, then refreshed `RC3-012` gate and `RC3-013` aggregate. All downstream negatives remain passed, publication-wave tasks remain blocked/planned, and `RC3-012` remains blocked pending real external production signatures.
- RC3 downstream negative fixture path-isolation hardening: the same five downstream `*-preconditions-fail-closed-fixtures.ps1` harnesses now reject unexpected `ArtifactDir` roots, require `OutputPath` to be a strict child of the expected `*-preconditions-negatives` artifact root, require case reset/write paths to be strict descendants, reject fixture reparse points before recursive delete/write, and route target preexists JSON fixtures through guarded case writers. Reran downstream negative harnesses and blocked precondition audits through `RC3-030`; current negatives remain `RC3-020=14/14`, `RC3-021=14/14`, `RC3-022=10/10`, `RC3-023=14/14`, `RC3-030=16/16`, active evidence parity is `passed` with 130/130 hashes, semantic consistency is `passed` with 33 checks, and no publication/consumer/support/gate/closeout output was generated.
- RC3-012 external return inbox completion-candidates harness hardening: `scripts/verify-rc3-external-return-inbox-completion-candidates-fail-closed-fixtures.ps1` now invokes the completion runner with `-FailOnBlocked`, resets/requires child inbox audit exit code `0`, requires blocked completion runner exit code `1` for both fixture return types, and clears final `$LASTEXITCODE` after a passed aggregate so callers do not misread expected blocked child runs as harness failure; reran the harness, `RC3-012` gate, `RC3-013` aggregate, and downstream blocked preconditions. This checkpoint has since been superseded by completion input and mode exclusivity hardening; `RC3-012` remains blocked pending real external production signatures.
- RC3-012 external return inbox candidate-readiness and negative harness hardening: `scripts/verify-rc3-external-return-inbox-candidate-readiness.ps1` and `scripts/verify-rc3-external-return-inbox-fail-closed-fixtures.ps1` now emit explicit child audit exit-code contract fields and child audit exit 0 case counts. `scripts/audit-rc3-012-completion-gate.ps1` and `scripts/verify-rc3-production-signing-fail-closed.ps1` now consume those counts, requiring 1 candidate-readiness child audit exit 0 case and 30 inbox negative child audit exit 0 cases while keeping `rc3_012_complete=false` / `rc3_012_may_advance=false`.
- RC3-012 active evidence hash parity and semantic consistency hardening: added `scripts/audit-rc3-active-evidence-hash-parity.ps1` plus `scripts/audit-rc3-active-evidence-semantic-consistency.ps1`, found and fixed a missing paired deliverable path for `signature_values_crypto_negative_completion_result_sha256`, and wired the parity/semantic summaries into `scripts/audit-rc3-012-completion-gate.ps1` plus `scripts/verify-rc3-production-signing-fail-closed.ps1` without recording parity or semantic result hashes, avoiding timestamp-driven self-reference loops. Expanded semantic stale-current-metric coverage across active evidence and TASK current summaries so old `173/68/128/129/6/4` and later `178/132/14/12/50/28` summaries are blocked, refreshed the affected `RC3-012` / `RC3-013` / `RC3-020` evidence text to the current `185/70/155` state, and reran gate / aggregate / downstream preconditions; active evidence parity is `passed` with 130/130 active evidence deliverable hashes matching, 130 deliverable hashes total, while `RC3-012` remains blocked pending real external production signatures.
- RC3-012 from-inbox wrapper TOCTOU hardening: `scripts/verify-rc3-external-return-inbox-completion-wrapper-fail-closed-fixtures.ps1` now covers audit-to-runner selected candidate hash drift plus completion-mode/input exclusivity coverage. The wrapper negatives are 7/7 with 5 pre-completion blocked cases; the two completion-entering cases still block at production cryptographic verification. Reran wrapper negatives, `RC3-012` gate, `RC3-013` aggregate, and downstream blocked preconditions; `RC3-012` remains blocked pending real external production signatures.
- RC3-013 production signing fail-closed aggregate script: `scripts/verify-rc3-production-signing-fail-closed.ps1`
- RC3-013 production signing fail-closed aggregate: `.workflow/artifacts/rc3-production-signing-fail-closed/result.json`（passed，70 checks，155 fail-closed negative cases，active evidence hash parity deliverable hashes=130，mismatches=0，active evidence semantic consistency checks=34，stale_pattern_hits=0，self_reference_hits=0，authority_leakage_hits=0，private_marker_hits=0，local signature boundary negative cases=1，signature values preflight negatives=12，signature values completion negatives=19，signature values receipt negatives=18，signature values inbound negatives=11，signature values input_path_negative_cases=3，signature bundle completion negatives=11，signature bundle input_path_negative_cases=3，signature bundle receipt negatives=15，required_input_cases=1，input_exclusivity_cases=1，mode_exclusivity_cases=2，external signer exchange freshness negative cases=10，external return inbox negative cases=30，external return inbox fixture input raw fields=329/370，raw_signature_values_archived=false，candidate-readiness cases=1，candidate-readiness json candidates=2，candidate-readiness child audit exit 0 cases=1，inbox negative child audit exit 0 cases=30，completion-candidate cases=2，completion-candidate crypto-blocked cases=2，completion-candidate child audit exit 0 cases=2，blocked completion exit 1 cases=2，completion wrapper status=blocked，completion wrapper invoked=false，completion wrapper negative cases=9，completion wrapper pre-completion blocked cases=7，completion wrapper selected-candidate hash mismatch cases=2，rc3_012_complete=false，rc3_012_may_advance=false，aggregate-only）
- RC3-013 aggregate evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-013-production-signing-fail-closed-fixtures.json`（completed，aggregate-only，does not advance RC3-012）
- RC3 current release reproducibility result: `.workflow/artifacts/release-reproducibility-fast/result.json`（passed，75 matched，0 divergent）
- RC3-020 release channel publication precondition audit script: `scripts/audit-rc3-release-channel-publication-preconditions.ps1`
- RC3-020 release channel publication preconditions: `.workflow/artifacts/rc3-release-channel-publication-preconditions/result.json`（blocked，43 checks，2 blockers，rc3_012_completion_gate_checks=185，rc3_012_completion_gate_fail_closed_negative_cases=155，production_signing_fail_closed_checks=70，production_signing_fail_closed_negative_cases=155，reproducibility_present=true，publication_ready=false，publication_manifest_written=false，channel_index_written=false，rc3_020_may_complete=false）
- RC3-020 release channel publication precondition fail-closed fixtures script: `scripts/verify-rc3-release-channel-publication-preconditions-fail-closed-fixtures.ps1`
- RC3-020 release channel publication precondition negatives: `.workflow/artifacts/rc3-release-channel-publication-preconditions-negatives/result.json`（passed，14/14 cases blocked，fixture_publication_files_are_isolated=true，publication_ready=false，rc3_012_complete=false，rc3_020_may_complete=false）
- RC3-020 blocked precondition evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-020-release-channel-publication-preconditions-blocked.json`（blocked-preconditions，does not advance RC3-012 or complete RC3-020）
- RC3-021 signed channel consumer precondition audit script: `scripts/audit-rc3-signed-channel-consumer-preconditions.ps1`
- RC3-021 signed channel consumer preconditions: `.workflow/artifacts/rc3-signed-channel-consumer-preconditions/result.json`（blocked，23 checks，9 blockers，publication_manifest_present=false，channel_index_present=false，publication_preconditions_ready=false，publication_precondition_negatives_passed=true，target_consumer_smoke_present=false，consumer_ready=false，consumer_smoke_executed=false，rc3_021_may_complete=false）
- RC3-021 signed channel consumer precondition fail-closed fixtures script: `scripts/verify-rc3-signed-channel-consumer-preconditions-fail-closed-fixtures.ps1`
- RC3-021 signed channel consumer precondition negatives: `.workflow/artifacts/rc3-signed-channel-consumer-preconditions-negatives/result.json`（passed，14/14 cases passed，fixture_target_files_are_isolated=true，consumer_ready=false，consumer_smoke_executed=false，publication_manifest_written=false，channel_index_written=false，rc3_021_may_complete=false）
- RC3-021 blocked precondition evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-021-signed-channel-consumer-preconditions-blocked.json`（blocked-preconditions，does not advance RC3-012 or complete RC3-021）
- RC3-022 published-release support/recovery precondition audit script: `scripts/audit-rc3-published-release-support-recovery-preconditions.ps1`
- RC3-022 published-release support/recovery preconditions: `.workflow/artifacts/rc3-published-release-support-recovery-preconditions/result.json`（blocked，21 checks，6 blockers，publication_manifest_present=false，channel_index_present=false，publication_preconditions_ready=false，consumer_preconditions_ready=false，production_verification_crypto_blockers=41，support_recovery_ready=false，rc3_022_may_complete=false）
- RC3-022 published-release support/recovery precondition fail-closed fixtures script: `scripts/verify-rc3-published-release-support-recovery-preconditions-fail-closed-fixtures.ps1`
- RC3-022 published-release support/recovery precondition negatives: `.workflow/artifacts/rc3-published-release-support-recovery-preconditions-negatives/result.json`（passed，10/10 cases passed，fixture_target_files_are_isolated=true，support_recovery_ready=false，support_bundle_written=false，recovery_projection_written=false，support_index_written=false，rc3_022_may_complete=false）
- RC3-022 blocked precondition evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-022-published-release-support-recovery-preconditions-blocked.json`（blocked-preconditions，does not advance RC3-012 or complete RC3-022）
- RC3-023 production signing/publication gate precondition audit script: `scripts/audit-rc3-production-signing-publication-gate-preconditions.ps1`
- RC3-023 production signing/publication gate preconditions: `.workflow/artifacts/rc3-production-signing-publication-gate-preconditions/result.json`（blocked，26 checks，8 blockers，production_verification_crypto_blockers=41，publication_manifest_present=false，channel_index_present=false，support_recovery_preconditions_ready=false，gate_integration_ready=false，rc3_023_may_complete=false）
- RC3-023 production signing/publication gate precondition fail-closed fixtures script: `scripts/verify-rc3-production-signing-publication-gate-preconditions-fail-closed-fixtures.ps1`
- RC3-023 production signing/publication gate precondition negatives: `.workflow/artifacts/rc3-production-signing-publication-gate-preconditions-negatives/result.json`（passed，14/14 cases passed，fixture_target_files_are_isolated=true，gate_integration_ready=false，gate_artifact_written=false，provenance_updated=false，publication_manifest_written=false，channel_index_written=false，rc3_023_may_complete=false）
- RC3-023 blocked precondition evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-023-production-signing-publication-gate-preconditions-blocked.json`（blocked-preconditions，does not advance RC3-012 or complete RC3-023）
- RC3-030 final closeout precondition audit script: `scripts/audit-rc3-final-closeout-preconditions.ps1`
- RC3-030 final closeout preconditions: `.workflow/artifacts/rc3-final-closeout-preconditions/result.json`（blocked，24 checks，11 blockers，final_audit_ready=false，final_audit_written=false，closeout_summary_written=false，production_verification_crypto_blockers=41，signing_publication_gate_present=false，rc3_030_may_complete=false）
- RC3-030 final closeout precondition fail-closed fixtures script: `scripts/verify-rc3-final-closeout-preconditions-fail-closed-fixtures.ps1`
- RC3-030 final closeout precondition negatives: `.workflow/artifacts/rc3-final-closeout-preconditions-negatives/result.json`（passed，16/16 cases passed，fixture_target_files_are_isolated=true，final_audit_ready=false，final_audit_written=false，closeout_summary_written=false，rc3_030_may_complete=false）
- RC3-030 blocked precondition evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-030-final-closeout-preconditions-blocked.json`（blocked-preconditions，does not advance RC3-012 or complete RC3-030）
- RC3-012 external signer handoff script: `scripts/create-rc3-external-signer-handoff.ps1`
- RC3-012 external signer handoff: `.workflow/artifacts/rc3-production-signature-verification/external-signer-handoff.json`（ready-for-external-signer，6 outbound files，34 checks）
- RC3-012 external signature bundle template script: `scripts/create-rc3-external-signature-bundle-template.ps1`
- RC3-012 external signature bundle template: `.workflow/artifacts/rc3-production-signature-verification/external-signature-bundle-template.json`（template-ready-for-external-signature-authoring，41 placeholders，not production proof）
- RC3-012 external signature values template script: `scripts/create-rc3-external-signature-values-template.ps1`
- RC3-012 external signature values template: `.workflow/artifacts/rc3-production-signature-verification/external-signature-values-template.json`（template-ready-for-external-signature-values，41 placeholders）
- RC3-012 external signing payload pack script: `scripts/export-rc3-external-signing-payload-pack.ps1`
- RC3-012 external signing payload pack: `.workflow/artifacts/rc3-production-signature-verification/external-signing-payload-pack/manifest.json`（ready-for-external-signer，41 payloads）
- RC3-012 external signature bundle assembly script: `scripts/assemble-rc3-external-signature-bundle.ps1`
- RC3-012 external signature bundle assembly missing-values negative: `.workflow/artifacts/rc3-production-signature-verification/external-bundle-assembly/missing-values-negative/result.json`（blocked，missing values=41）
- RC3-012 external signature bundle assembly placeholder-values negative: `.workflow/artifacts/rc3-production-signature-verification/external-bundle-assembly/placeholder-values-negative/result.json`（blocked，placeholder values=41）
- RC3-012 external signer handoff package verifier script: `scripts/verify-rc3-external-signer-handoff-package.ps1`
- RC3-012 external signer handoff package verification: `.workflow/artifacts/rc3-production-signature-verification/external-signer-handoff-package-verification.json`（passed，6 outbound files，41 payloads，164 checks，read-boundary guards passed）
- RC3-012 external signature bundle template audit: `.workflow/artifacts/rc3-production-signature-verification/external-signature-bundle-template-audit.json`（blocked，0 eligible external bundles）
- RC3-012 template negative completion: `.workflow/artifacts/rc3-production-signature-verification/template-negative/completion-result.json`（blocked at availability audit）
- RC3-012 structural fixture negative completion: `.workflow/artifacts/rc3-production-signature-verification/structural-fixture-negative/completion-result.json`（blocked at availability audit）
- RC3-012 blocked evidence: `.workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/RC3-012-production-signature-verification-blocked.json`

### RC3 Wave 0：signing ceremony and publication contracts

- `RC3-001`：定义 external production signing ceremony and release publication contract（completed）
- `RC3-002`：定义 production signature bundle intake、custody、rotation and revocation boundary（completed）
- `RC3-003`：定义 immutable release channel publication and rollback boundary（completed）
- `RC3-004`：定义 production signing and release publication threat model（completed）

退出标准：

- ceremony contract 明确 signing request package、external signer boundary、public fingerprint、rotation epoch、revocation check 和 no-private-material rule。
- release channel contract 明确 immutable/content-addressed publication、rollback evidence、revocation handling 和 channel tamper fail-closed。
- threat model 覆盖 missing signature、candidate signature substitution、wrong artifact hash、revoked key、rotation drift、private material leak、channel tamper、rollback absence 和 TUI mutation attempt。

### RC3 Wave 1：external signature intake and verification

- `RC3-010`：实现 external signing request export package and redaction verifier（completed）
- `RC3-011`：实现 external production signature bundle intake without local private material（completed）
- `RC3-012`：扩展 production signature verification to RC2 true block-device decision evidence（completed）
- `RC3-013`：实现 production signing fail-closed fixtures（completed，aggregate-only）

退出标准：

- signing request export package 包含 RC2 true block evidence、release provenance、candidate promotion、reproducibility 和 signing request hashes，且不含 private/secret-like material。
- signature bundle intake 只接受 external production detached signatures，拒绝 candidate-only、hash mismatch、revoked key、rotation mismatch、malformed bundle 和 local private material。
- production signature verification 覆盖 RC2 true block-device artifact classes。

### RC3 Wave 2：release publication and consumer proof

- `RC3-020`：实现 immutable release channel publication manifest with external signatures（completed）
- `RC3-021`：增加 signed release channel consumer and rollback smoke from installed block-device evidence（completed）
- `RC3-022`：增加 published-release support bundle and recovery projection（completed）
- `RC3-023`：把 production signing and release publication evidence 接入 provenance / promotion gates（completed）

退出标准：

- release channel publication manifest 绑定 external production signatures、RC2 true block evidence、rollback baseline、revocation state 和 immutable index hash。
- signed channel consumer smoke 可从 installed block-device evidence 验证 published release，不执行 activation mutation。
- promotion gate 在 external signatures、channel publication、rollback/revocation 或 RC2 true block evidence missing / skipped / failed 时阻塞。

### RC3 Wave 3：RC3 closeout

- `RC3-030`：运行 Production Distro RC3 final audit and next milestone planning（completed）

退出标准：

- release provenance、candidate promotion、production signature verification、reproducibility 和 signing/publication gate 都包含 external production signing and release publication decision evidence。
- RC3 final audit 明确 external signing / publication 的证明范围、仍未覆盖的 GA gap 和下一 milestone。

### RC4 Wave 0：hosted transport and fleet rollout contracts

- `RC4-001`：定义 hosted release transport、registry mirror and fleet-ring boundary（completed）
- `RC4-002`：定义 staged rollout authority and rollback boundary（completed）
- `RC4-003`：定义 GA hardening acceptance gates and non-GA boundary（completed）
- `RC4-004`：定义 hosted transport and fleet rollout threat model（completed）

退出标准：

- hosted release transport metadata 绑定 RC3 final audit、production verification、publication manifest、channel index 和 signing/publication gate。
- fleet rollout authority 保持 AgentCore PlanSpec + SecurityExecutionEngine；TUI、model replay、normal shell 和 remote control plane 不能直接拥有 mutation authority。
- RC4 明确不是 GA production-ready claim，直到 hosted transport、fleet、rollback、revocation、support 和 promotion gates 全部闭合。

### RC4 Wave 1：hosted transport and mirror replay

- `RC4-010`：实现 hosted release transport manifest and local mirror fixture（completed）
- `RC4-011`：实现 remote registry mirror publication replay（completed）
- `RC4-012`：实现 fleet-ring rollout plan precondition audit（completed）
- `RC4-013`：实现 hosted transport fail-closed fixtures（completed）

退出标准：

- hosted manifest、mirror snapshot、registry lockfile、rollback baseline 和 revocation/advisory snapshot 都可 hash-bound。
- stale、missing、tampered、unsigned、revoked 或 untrusted mirror metadata fail closed。

### RC4 Wave 2：fleet rollout、support and gates

- `RC4-020`：增加 signed hosted-channel consumer and mirror smoke（completed）
- `RC4-021`：增加 staged fleet-ring rollout smoke and rollback drill（completed）
- `RC4-022`：增加 GA-hardening support and recovery projection（completed）
- `RC4-023`：把 hosted transport and fleet evidence 接入 promotion gates（completed）

退出标准：

- staged rollout 不执行 active-slot mutation，直到 exact operator approval、rollback baseline 和 SecurityExecutionEngine gate 都满足。
- support bundle 能解释 hosted transport / fleet ring / mirror 状态且不包含 raw secrets。

### RC4 Wave 3：RC4 closeout

- `RC4-030`：运行 Production Distro RC4 final audit and next milestone planning（completed）

退出标准：

- hosted transport、remote registry mirror、fleet rollout、rollback、revocation、support 和 promotion evidence 均可审计。
- final audit 明确 RC4 的证明范围、仍未覆盖的 GA gap 和下一 milestone。
- `TASK-PROD-050` 已完成：support bundle 现在包含 Agent Runtime loop、recovery、ecosystem registry/lockfile/active set、replay、revocation 和 offline baseline 状态，且不泄漏 raw secrets；`agentd` 仍是只读 projection，不拥有 resolver logic。
- `TASK-PROD-051` 已完成：release update metadata / provenance 已加入 active artifact set hash、runtime contract compatibility、rollback previous active set evidence 和 promotion blockers；当前 `promotion.status=promotable` 且 blockers 为空。
- `TASK-PROD-052` 已完成：ecosystem replay 增加 offline pinned snapshot drill；expired local registry snapshot 会 fail closed，并投影为 `degraded-expired-snapshot`。
- `TASK-PROD-053` 已完成：final Production Distro chain audit 和 summary 已写入 `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/docs/final-chain-audit-summary.md`。
- Distribution Alpha 已在前序 workflow 完成：`.workflow/active/WFS-20260523-agentos-distribution-alpha`。
- `TASK-DALPHA-000` 已完成：Distribution Alpha scope 和任务图已冻结，新的 workflow、plan、context、task plan、`TASK-DALPHA-001` 到 `TASK-DALPHA-012` 均已写入 `.workflow/active/WFS-20260523-agentos-distribution-alpha`。
- `TASK-DALPHA-001` 已完成：rootfs runtime artifact install manifest 已定义，覆盖 boot/runtime `agentd`、policy pack、semantic tool manifest、ModelBroker config、run/audit/rollback/memory persistent directories、release provenance 和 rootfs manifest metadata，并提供后续 validator 可消费的 artifact ID 与 validation labels。
- `TASK-DALPHA-002` 已完成：runtime state directory and permission validation 已定义，覆盖 `/var/lib/agentos/runs/`、`/var/log/agentos/audit/`、`/var/lib/agentos/rollback/` 和 `/var/lib/agentos/memory/` 的 `root:root` / `0700` 初始权限、runtime authority、secret-safety、restart-survival、audit projection、recovery truth 和 evidence schema。
- `TASK-DALPHA-004` 已完成：packageable policy pack、semantic tool manifest 和 ModelBroker defaults 已写入 `packaging/agentos/rootfs/etc/agentos/`，保留 exact approval binding，normal-mode `shell.exec` 只作为 deny policy 出现且不在 semantic tool manifest 中，ModelBroker 默认 stub/local-only 且不需要 network 或 external credentials。
- `TASK-DALPHA-003` 已完成：新增 `scripts/validate-alpha-rootfs.ps1`，可在 `PackageDefaults` 阶段验证 `policy.pack`、`tools.semantic`、`model_broker.config` 和四个 persistent state directories，输出稳定 JSON；缺失 `model_broker.config` 的 fixture 已验证 fail-closed。
- `TASK-DALPHA-005` 已完成：新增 `image/build-alpha-rootfs.ps1`，并让 `image/build-initramfs.ps1` 默认执行 Alpha rootfs validation / staging；生成的 initramfs manifest 已嵌入 Alpha rootfs manifest、runtime artifact hashes、rootfs runtime manifest hash 和 blocking Alpha risks，boot handoff 仍保持 `/sbin/agentd` / `AGENTD_HANDOFF_OK`。
- `TASK-DALPHA-006` 已完成：新增 `scripts/alpha-service-recovery-smoke.ps1`，从 staged Alpha rootfs runtime contracts 运行 approved / denied generic AgentCore service recovery；approved restart-service 投影为 sealed 且 `CommitSealed=true`，denied restart-service 记录 `PolicyEvaluated` 且 `EffectPrepared=0`，ModelBroker 保持 stub/local-only，无需外部 LLM。
- `TASK-DALPHA-007` 已完成：`image/build-initramfs.ps1` 会把 `AGENTOS_RUNTIME_ARTIFACTS_OK` 和 rootfs runtime manifest hash marker 嵌入 early `/sbin/agentd`，`scripts/boot-smoke-test.ps1` 已从 handoff-only gate 升级为 runtime-aware QEMU gate；完整 QEMU smoke 观察到 `AGENTD_HANDOFF_OK`、runtime marker 和 runtime manifest hash marker。
- `TASK-DALPHA-008` 已完成：`scripts/build-release.ps1` 已升级为 `agentos.distribution-alpha.provenance.v1` promotion gate，记录 source revision、toolchain、dependency inventory、runtime manifest hash、image inputs、artifact hashes、Alpha service recovery smoke、full QEMU runtime smoke 和 gate commands；本次 gate 结果为 `promotion.status=promotable`，blockers 为空。
- 已按 Maestro 方式补充 Agent Core Runtime 和 AgentOS 安全执行底座的 Alpha 延续展开：`.workflow/active/WFS-20260523-agentos-distribution-alpha/docs/agent-core-runtime-security-execution-expanded-tasks.md`。这份文档把 `TASK-ACR-001` 到 `TASK-ACR-010`、`TASK-SEF-001` 到 `TASK-SEF-010`、`TASK-DALPHA-009` 到 `TASK-DALPHA-012` 串成从底层 Agent runtime 到发行版安全执行面的执行链。
- `TASK-DALPHA-009` 已完成：Firecracker executor profile 已放到 SecurityExecutionEngine 后面，缺 KVM、Firecracker binary、jailer、kernel image 或 rootfs image 会在 `EffectPrepared` 前 fail closed；planner hints 只记录为 ignored，profile selection 和 policy reason 进入 audit/explain，没有新增直接 Firecracker 执行 helper。
- `TASK-DALPHA-010` 已完成：新增 `agent_core::package_install` Alpha workflow contract，第三方包安装必须先经过 metadata fetch、isolated install、isolated smoke test、host checkpoint，再凭绑定 package、version、source URI、source digest 和 rollback id 的 exact approval 才能 host promotion；external/model source、失败隔离验证、缺 rollback/checkpoint 或 raw artifacts 都会 fail closed 且 `host_modified=false`，`safety::` 已纳入 `runtime-package-install-host-promotion-bypass`。
- `TASK-DALPHA-011` 已完成：新增 `agent_core::untrusted_content` Alpha workflow contract，外部内容经过 fetch、sanitize、summarize、source-to-sink policy check 和 audit projection；sanitized summary 只能作为 replanning context，不能直接驱动 shell、secret、privileged、package install 或 exfiltration sink，denied action 会进入 RuntimeAuditProjection 且无 `EffectPrepared`，`safety::` 已纳入 `runtime-untrusted-content-direct-sink-bypass`。
- `TASK-DALPHA-012` 已完成：Distribution Alpha final audit 已在 clean detached worktree `56278f05d4ca078efe18a3be7aa42d8789a5490f` 上复跑通过，覆盖 `cargo test -p agentd` 178 passed、`safety::` 18 passed、`agent_core::` 77 passed、`agent_core::adversarial` 5 passed、`scripts/build-release.ps1` 和 `E:\qemu\qemu-system-x86_64.exe` full QEMU runtime smoke；promotion decision 为 `promotable`，blockers 为空。
- Runtime Foundation 已完成执行与 final audit：6 个 wave，26 个 task，覆盖 Agent Core Runtime、Security Execution Foundation 和 Distribution Alpha 入口门槛。
- `TASK-RTF-000` 已完成：Agent Core Runtime 和 Security Execution Foundation 边界已冻结为 accepted decision，AgentCore 初始实现选择 in-process inside `agentd`，Distribution Alpha 被阻塞到 generic AgentCore runtime 通过验收。
- `TASK-RTF-001` 已完成：runtime states、state transitions、audit event mapping、RunStore/AuditJournal source of truth、idempotency 和 recovery policy 已冻结为 contract。
- `TASK-RTF-002` 已完成：runtime module ownership、integration points、audit write rules、CLI/TUI entry points 和 duplicate-stack prohibition 已冻结。
- `TASK-RTF-003` 已完成：MVP safety invariants 已提升为 Runtime Foundation gate，`cargo test -p agentd` 49 passed，`cargo test -p agentd safety::` 8 passed。
- `TASK-ACR-001` 已完成：新增 `agent_core::model` 版本化 runtime 数据模型，覆盖 `IntentCtx`、`PlanSpec`、`PlanStep`、`PlanRun`、`Observation`、稳定 JSON、secret-like 拒绝和 advisory risk hints，`cargo test -p agentd` 56 passed。
- `TASK-ACR-002` 已完成：新增 `agent_core::run_store`，提供 `RunStore` trait、`FileRunStore` 快照持久化、recoverable run 查询、observation hash、tamper detection 和 AuditJournal seal 对照，`cargo test -p agentd` 63 passed。
- `TASK-ACR-003` 已完成：新增 `agent_core::model_broker`、`ModelBroker` trait 和 deterministic `StubModelProvider`，覆盖 plan/classify/summarize/sanitize、metadata-only call log、bounded output、timeout/cancel/failure fail-closed 和 invalid output rejection，`cargo test -p agentd` 70 passed。
- `TASK-ACR-004` 已完成：新增 `agent_core::planner`、deterministic planner、PlanSpec validator 和 freeze hash，规划阶段只写 IntentReceived / PlanFrozen，拒绝 shell.exec、unknown tool、缺 rollback 写入和 secret-like plan，`cargo test -p agentd` 78 passed。
- `TASK-SEF-001` 已完成：新增 `security_execution::effect_envelope`，定义 side effect transaction envelope、Draft/Prepared/Observed/Verified/Sealed/RollbackPending/RolledBack/FailedClosed 状态机、AuditJournal 事件绑定、成功 verification 后才能 CommitSealed、failed write-with-diff verification 必须进入 RollbackPending，以及 secret-like 序列化拒绝，`cargo test -p agentd` 84 passed。
- `TASK-SEF-002` 已完成：新增 `security_execution::policy_adapter`，把 generic `PlanStep` 接入 `ToolRouter`、`PolicyEvaluator`、approval token 和 `CapabilityLease`，policy 风险分类覆盖 planner risk hints，denied / paused 路径只写 PolicyEvaluated、不准备 effect，`cargo test -p agentd` 90 passed。
- `TASK-SEF-003` 已完成：强化 lease-derived sandbox profile，`SandboxProfile` 序列化现在投影 namespace、cgroup、seccomp、filesystem、Landlock 和 network allowlist；新增 `security_execution::sandbox_profile`，只接受 `CapabilityLease` 作为 profile authority，planner sandbox weakening hints 会被记录为 ignored，unsupported risk classes fail closed，`cargo test -p agentd` 96 passed。
- `TASK-SEF-004` 已完成：新增 `security_execution::source_to_sink`，定义 operator/local/external/model/sanitized source labels 和 read/write/execute/privileged/network/secret sink classes，阻断 untrusted 或 model-origin content 直接驱动高风险 sink，denied 路径只写 PolicyEvaluated 且不准备 effect，`safety::prompt_injection` 直接覆盖该 policy，`cargo test -p agentd` 104 passed。
- `TASK-SEF-005` 已完成：新增 `security_execution::secret_runtime`，定义 `SecretHandle` metadata、raw secret forbidden surfaces、handle-preserving redaction、one-shot `SecretUseLease`、broad approval 拒绝和 handle-only audit，`safety::secret` 直接覆盖该 policy，`cargo test -p agentd` 114 passed。
- `TASK-ACR-005` 已完成：新增 `agent_core::run_loop`，实现 `AgentCore` 的 `accept_intent`、`plan_run`、`advance_run`、`approve_step`、`deny_step`、`suspend_run`、`recover_run` 和 compact projection；状态转移先通过 `RunStore` 落盘，read-only step 通过 `EffectEnvelope` 自动 prepare/observe/verify/seal，高风险 step 暂停且不准备 effect，denied/timeout 不执行受保护动作，`cargo test -p agentd` 121 passed。
- `TASK-ACR-006` 已完成：新增 `agent_core::scheduler`，实现 dependency-aware `StepScheduler`、DAG 校验、CommitSealed-backed ready-step selection、denied dependency blocking、retry budget fail-closed 和 deterministic scheduler explanation；Planner freeze 前会拒绝 missing dependency / cycle，AgentCore run loop 已改用 scheduler decision，`cargo test -p agentd` 128 passed。
- `TASK-ACR-007` 已完成：新增 `agent_core::observation`，实现 `ObservationProcessor`、observation trust labels、secret-like redaction、untrusted content sanitization、policy flag extraction、direct action source-to-sink denial 和 run loop observation ref 接入；observation 文本只能生成 sanitized replanning hint，不能直接创建 tool call，`cargo test -p agentd` 132 passed。
- `TASK-ACR-008` 已完成：新增 `agent_core::memory`，实现 `MemoryStore` trait、`InMemoryMemoryStore`、session/run/audit-derived/quarantined scopes、entry metadata、TTL expiry、bounded Planner context、secret-like redaction 和 suspicious/untrusted quarantine；memory poisoning 不能把 policy override、capability lease 或 approval claim 注入 Planner context，`cargo test -p agentd` 137 passed。
- `TASK-SEF-006` 已完成：新增 `security_execution::engine`，实现 `SecurityExecutionEngine` trait 和 `DefaultSecurityExecutionEngine`，统一 prepare / execute / observe / verify / seal / rollback / explain API；prepare 贯通 ToolRouter、PolicyEvaluator、CapabilityLease、lease-derived sandbox profile、EffectEnvelope、AuditJournal 和 write-with-diff rollback handle，denied / paused 不准备 effect，`cargo test -p agentd` 142 passed。
- `TASK-SEF-007` 已完成：新增 `agent_core::recovery`，实现 `AgentRunRecoveryCoordinator`，把 RunStore recoverable runs 与 AuditJournal durable effect truth 联合分类为 safe-to-verify、needs-rollback、needs-human-review、abandoned、failed-closed 或 completed，并恢复到 Recovering、Suspended、RollbackPending、Completed 或 FailedClosed；恢复 projection 明确 source=run-store+audit 且 no-model-replay，`cargo test -p agentd` 150 passed。
- `TASK-ACR-009` 已完成：service recovery 已迁移到 generic AgentCore runtime，Planner 产出完整 nginx recovery DAG，旧 `ServiceRecoveryWorkflow` 仅作为兼容 wrapper 委托到 `agent_core::service_recovery`，approved/denied CLI demo 和 latest audit timeline 均通过，`cargo test -p agentd` 153 passed。
- `TASK-ACR-010` 已完成：新增 `agent_core::adversarial` runtime abuse suite，覆盖 planning prompt injection、observation injection、memory poisoning、approval parameter mutation 和 malformed model output；CI safety / release gate 已加入 `cargo test -p agentd agent_core::adversarial`，`cargo test -p agentd` 158 passed。
- `TASK-SEF-008` 已完成：`SafetyGateConfig` 已升级为 generic Agent execution gate，required scenarios 纳入 model output injection、observation injection、memory poisoning、approval mutation、source-to-sink abuse 和 runtime recovery abuse，并要求同时运行 `cargo test -p agentd safety::` 与 `cargo test -p agentd agent_core::adversarial`，`cargo test -p agentd` 158 passed。
- `TASK-SEF-009` 已完成：新增 `RuntimeAuditProjection`，CLI `--audit-project` 和 TUI render helper，覆盖 latest / run-id、stable ordering、redaction、denied / no-effect、recovery source；`cargo test -p agentd` 163 passed。
- `TASK-SEF-010` 已完成：Security Execution Foundation final verification 已通过，覆盖 `cargo test -p agentd` 163 passed、`safety::` 16 passed、`agent_core::adversarial` 5 passed、`agent_core::service_recovery` 3 passed、approved / denied service recovery CLI smoke、runtime audit projection、release/provenance gate、initramfs build 和 QEMU dependency check。
- Runtime Foundation Wave 1 已完成：Agent Core Contracts 的数据模型、RunStore、ModelBroker 和 Planner 均已验证。
- Runtime Foundation Wave 2 已完成：EffectEnvelope、policy adapter、lease-derived sandbox profile、source-to-sink policy 和 secret handle lease rules 均已验证。
- Wave 0 已完成：产品形态、运行假设、scope control 和 Wave 1 入口约束均已冻结。
- Wave 1 已完成：boot handoff、`agentd` lifecycle skeleton 和 terminal-first TUI surface 均已验证。
- Wave 2 已完成：semantic tool routing、append-only audit journal 和 recovery reconciler 均已验证。
- Wave 3 已完成：capability lease model、read-only sandbox executor 和 write-with-diff rollback flow 均已验证并归档。
- Wave 4 已完成：service recovery workflow、safety regression gate 和 release provenance flow 均已验证并归档。
- 最终全量完成审计已通过：所有 task JSON 为 `completed`，`.workflow` JSON 可解析，`cargo test -p agentd` 通过，release pipeline 通过，QEMU boot smoke 观察到 `AGENTD_HANDOFF_OK`。
- `TASK-AIOS-001` 已完成：最小 initramfs 通过 `E:\qemu\qemu-system-x86_64.exe` 启动，并观察到 `/sbin/agentd` 输出 `AGENTD_HANDOFF_OK`。
- `TASK-AIOS-002` 已完成：Rust `agentd` lifecycle skeleton 提供 local-only/stub 模式、健康状态、模块边界和 typed stub APIs。
- `TASK-AIOS-003` 已完成：terminal-first TUI surface 支持 intent、plan preview、approval/denial/timeout/suspended 和 audit projection。
- `TASK-AIOS-004` 已完成：semantic tool schema/router 支持 normalized params、`fs.write.diff` 风险分类，并拒绝 normal-mode `shell.exec`。
- `TASK-AIOS-005` 已完成：append-only JSONL audit journal 支持核心事件、未封口 effect 查询和 secret-like summary redaction。
- `TASK-AIOS-006` 已完成：recovery reconciler 可分类未完成 effect，写入 RecoveryStarted/Completed，并为写入类 effect 要求人工确认。
- `TASK-AIOS-007` 已完成：policy evaluator 支持 allow / deny / pause-for-approval，approval token 绑定 exact parameter hash，并记录 denied decision without execution。
- `TASK-AIOS-008` 已完成：read-only lease 可编译为 Linux sandbox profile，persistent write、fork fanout 和 denied syscall 均被 guard 拦截并记录。
- `TASK-AIOS-009` 已完成：`fs.write.diff` 先生成 shadow diff 和 rollback handle，commit 写入完整 audit 链，rollback 可恢复旧内容。
- `TASK-AIOS-010` 已完成：nginx service recovery fixture 可端到端运行，restart 需确认，denied 路径不准备 restart effect。
- `TASK-AIOS-011` 已完成：safety gate 覆盖 prompt injection、tool abuse、resource abuse、secret handle、rollback/recovery failure，并接入 CI。
- `TASK-AIOS-012` 已完成：release pipeline 可生成 agentd release build、initramfs、dependency inventory 和 provenance metadata。
- `TASK-RTF-004` 已完成：Distribution Alpha entry criteria 已定义，明确 Alpha 不能只从 MVP skeleton 启动，必须继承 generic AgentCore、Security Execution Foundation、rootfs runtime artifacts、persistent runtime directories、release/provenance 和 QEMU gates。
- `TASK-RTF-005` 已完成：Runtime Foundation final audit 已通过，覆盖 54 个 workflow JSON 解析、`cargo test -p agentd` 163 passed、`safety::` 16 passed、`agent_core::` 68 passed、release/provenance gate 和 `E:\qemu\qemu-system-x86_64.exe` 完整 QEMU boot smoke。
- Runtime Foundation workflow 已完成；Distribution Alpha planning 已启动并完成 `TASK-DALPHA-000`。

## Distribution Alpha 任务计划

目标：把已完成的 Agent Core Runtime 和 Security Execution Foundation 装进可发行的 AgentOS Alpha rootfs / VM image 路径。Alpha 不能只复用 MVP handoff skeleton，必须安装并验证 `agentd`、policy pack、semantic tool manifest、ModelBroker config、run/audit/rollback/memory persistent directories、release/provenance metadata 和 QEMU runtime smoke。

关键约束：

- Distribution Alpha 依赖 `TASK-RTF-005` Runtime Foundation final audit。
- Stub/local-only ModelBroker mode 必须可运行；外部 LLM 不能成为验收依赖。
- Firecracker 是 Alpha executor profile，必须位于 `SecurityExecutionEngine` 后面，不能成为并行 side-effect path。
- 所有 promotion gate 必须继承 runtime、safety、AgentCore、adversarial、release 和 QEMU 验证。
- 生成的 image、cache、release artifact 和 boot log 不能进入提交。
- Alpha 视角的底层 Agent 与安全执行 TASK 展开见 `.workflow/active/WFS-20260523-agentos-distribution-alpha/docs/agent-core-runtime-security-execution-expanded-tasks.md`。

### Distribution Alpha Wave 0：Alpha scope 与 packaging contract

- `TASK-DALPHA-000`：冻结 Distribution Alpha scope and task graph（completed）
- `TASK-DALPHA-001`：定义 rootfs runtime artifact install manifest（completed）
- `TASK-DALPHA-002`：定义 runtime state directory and permission validation（completed）
- `TASK-DALPHA-004`：package policy pack、semantic tool manifest 和 ModelBroker defaults（completed）

退出标准：

- Alpha scope 明确拒绝 MVP skeleton-only promotion。
- rootfs manifest 覆盖 `agentd`、policy、tools、ModelBroker、run-state、audit、rollback、memory 和 release metadata。
- state directory permission、secret-safety 和 restart-survival 验证可被后续脚本消费。

### Distribution Alpha Wave 1：runtime-aware image assembly

- `TASK-DALPHA-003`：实现 rootfs staging and manifest validation（completed）
- `TASK-DALPHA-005`：assemble runtime-aware initramfs and rootfs image path（completed）

退出标准：

- image/rootfs assembly 必须先通过 runtime manifest validation。
- assembly manifest 记录 runtime artifact hashes 和 image inputs。
- QEMU handoff 仍兼容 `/sbin/agentd` 或 accepted equivalent。

### Distribution Alpha Wave 2：packaged runtime proofs

- `TASK-DALPHA-006`：运行 packaged AgentCore service recovery smoke（completed）
- `TASK-DALPHA-007`：增加 QEMU boot and runtime smoke gate（completed）
- `TASK-DALPHA-008`：增加 Distribution Alpha release/provenance promotion gate（completed）

退出标准：

- packaged runtime 能跑 approved / denied service recovery。
- QEMU smoke 证明 boot handoff 和 packaged runtime availability。
- provenance 记录 runtime manifest、image inputs、artifact hashes 和 gate commands。

### Distribution Alpha Wave 3：Alpha isolation workstreams

- `TASK-DALPHA-009`：把 Firecracker executor profile 放到 SecurityExecutionEngine 后面（completed）
- `TASK-DALPHA-010`：增加 package install isolation workflow（completed）
- `TASK-DALPHA-011`：增加 untrusted content runtime workflow（completed）

退出标准：

- Firecracker 不绕过 semantic tools、policy、capability、EffectEnvelope、audit、rollback 或 recovery。
- package install 不能未经验证和精确审批直接落到 host。
- untrusted content 不能直接驱动 shell、secret、privileged 或 exfiltration sink。

### Distribution Alpha Wave 4：Alpha promotion audit

- `TASK-DALPHA-012`：完成 Distribution Alpha final audit and promotion decision（completed）

退出标准：

- 所有 Alpha evidence 可追溯。
- runtime、safety、AgentCore、adversarial、release 和 QEMU gates 均有直接证据。
- 明确记录 promotion decision 或 blocking risks。

## Runtime Foundation 任务计划

目标：把已完成的 AgentOS MVP 安全底座，推进成真正的底层 Agent runtime。也就是让 `agentd` 不再只是 lifecycle skeleton、stub planner 和手写 workflow，而是具备通用的 Agent Core：接收 intent、生成冻结计划、调度步骤、处理观察、更新 memory、暂停审批、执行受控工具、恢复中断 run。

### 两层边界

- Agent Core Runtime：负责 intent、PlanSpec、PlanRun、ModelBroker、Planner、StepScheduler、ObservationProcessor、Memory 和 TUI/API run-state projection。
- Security Execution Foundation：负责 semantic tool、policy、capability lease、sandbox、EffectEnvelope、audit、verification、rollback 和 recovery。

关键约束：

- Model output 只能提出结构化计划或摘要，不能直接执行 tool。
- 所有 side effect 必须经过 Security Execution Foundation。
- Planner 的 risk hint 不是权限，PolicyEvaluator 才是权威。
- Observation 和 external content 默认不可信，不能直接触发高风险 sink。
- Memory 不允许保存 secret 明文或未经标记的不可信指令。
- Distribution Alpha 在 Runtime Foundation final audit 通过前不得启动。

详细 TASK 展开：

- Agent Core Runtime 和 Security Execution Foundation 的 worker-facing 实施蓝图已经写入 `.workflow/active/WFS-20260522-agentos-runtime-foundation/docs/runtime-implementation-tasks.md`，逐任务详细规格已经写入 `.workflow/active/WFS-20260522-agentos-runtime-foundation/docs/agent-core-sef-detailed-tasks.md`。
- Distribution Alpha 的延续执行视角已经写入 `.workflow/active/WFS-20260523-agentos-distribution-alpha/docs/agent-core-runtime-security-execution-expanded-tasks.md`，把已完成的 ACR/SEF foundation 映射到 Firecracker profile、package install isolation、untrusted content workflow 和 final promotion audit。
- Agent Core Runtime 的底层实现链路固定为 `IntentCtx -> ModelBroker -> Planner -> PlanSpec -> RunStore -> StepScheduler`，它只负责意图、计划、状态、调度、观察、memory 和 projection。
- AgentOS 安全执行底座固定为 `SecurityExecutionEngine -> PolicyAdapter -> CapabilityLease -> SandboxProfile -> EffectEnvelope -> AuditJournal -> VerificationResult -> CommitSealed/RollbackPending/FailedClosed`，它是唯一 side-effect path。
- `TASK-ACR-001` 到 `TASK-ACR-010`、`TASK-SEF-001` 到 `TASK-SEF-010` 均已补充 `read_first`、`implementation_steps`、`failure_modes`、`verification_matrix` 和 `handoff`，后续可直接按 Maestro 执行或审计。

### Runtime Foundation Wave 0：边界冻结

- `TASK-RTF-000`：冻结 Agent Core 和 Security Execution Foundation 边界（completed）
- `TASK-RTF-001`：定义 runtime state transitions 和 audit event mapping（completed）
- `TASK-RTF-002`：定义模块 ownership 与 runtime integration points（completed）
- `TASK-RTF-003`：把 MVP safety invariants 继承为 runtime gates（completed）

退出标准：

- AgentCore、ModelBroker、Memory、Planner、Scheduler、Policy、Capability、Audit、Rollback、Recovery 的职责明确。
- 没有 model-to-tool direct execution、planner-to-shell 或未记账写入路径。
- 已完成 MVP 的安全约束变成新 runtime 的入场门。

### Runtime Foundation Wave 1：Agent Core Contracts

- `TASK-ACR-001`：定义 Agent runtime data model（completed）
- `TASK-ACR-002`：实现 persistent PlanRun store（completed）
- `TASK-ACR-003`：实现 ModelBroker trait 和 stub provider（completed）
- `TASK-ACR-004`：实现 Planner，冻结结构化 PlanSpec（completed）

退出标准：

- `IntentCtx`、`PlanSpec`、`PlanStep`、`PlanRun`、`Observation`、`RunState` 可序列化、可恢复、可审计。
- `ModelBroker` 是唯一模型边界，并支持 local-only stub provider。
- Planner 只能冻结计划，不能执行 side effect。

### Runtime Foundation Wave 2：安全执行底座强化

- `TASK-SEF-001`：定义 generic EffectEnvelope contract（completed）
- `TASK-SEF-002`：创建 Agent step policy / capability adapter（completed）
- `TASK-SEF-003`：强化 lease-derived sandbox profile compilation（completed）
- `TASK-SEF-004`：定义 untrusted content source-to-sink policy（completed）
- `TASK-SEF-005`：实现 secret handle lease rules for Agent runtime（completed）

退出标准：

- 每个 side effect 都有 `EffectEnvelope`，从 prepare 到 seal / rollback 可追踪。
- AgentCore 只能通过 policy adapter 申请执行。
- Sandbox profile 从 capability lease 编译，不能由 planner 降级。
- untrusted content 和 secret handle 有明确 source-to-sink 约束。

### Runtime Foundation Wave 3：Generic Agent Run Loop

- `TASK-ACR-005`：实现 AgentCore run loop state machine（completed）
- `TASK-ACR-006`：实现 dependency-aware StepScheduler（completed）
- `TASK-ACR-007`：实现 ObservationProcessor 和 trust boundary handling（completed）
- `TASK-ACR-008`：实现最小 Agent memory layer（completed）
- `TASK-SEF-006`：实现 generic SecurityExecutionEngine bridge（completed）
- `TASK-SEF-007`：集成 recovery reconciler 与 Agent run state（completed）

退出标准：

- `PlanRun` 可经过 Accepted、Planning、Planned、AwaitingApproval、Executing、Observing、Verifying、Completed、Suspended、RollbackPending、Recovering。
- read-only step 可以自动执行并 seal，高风险 step 必须暂停审批。
- observation 不能直接变成 tool call。
- crash/restart 可以从 RunStore + AuditJournal 恢复状态。

### Runtime Foundation Wave 4：workflow 迁移与安全门

- `TASK-ACR-009`：把 service recovery 迁移到 generic AgentCore runtime（completed）
- `TASK-ACR-010`：加入 AgentCore adversarial runtime tests（completed）
- `TASK-SEF-008`：扩展 generic Agent execution safety gate（completed）
- `TASK-SEF-009`：构建 runtime audit projection 和 explainability chain（completed）
- `TASK-SEF-010`：运行 Security Execution Foundation final verification（completed）

退出标准：

- nginx service recovery 不再依赖专用手写 workflow，而是通过 generic AgentCore `PlanRun`。
- prompt injection、observation injection、memory poisoning、approval bypass、tool abuse、secret leak、half-committed effect 都进入 safety gate。
- TUI/CLI 可以解释每一步为什么运行、暂停、拒绝、回滚或 seal。

### Runtime Foundation Wave 5：发行版入口桥接

- `TASK-RTF-004`：定义 Distribution Alpha entry criteria from runtime foundation（completed）
- `TASK-RTF-005`：完成 Runtime Foundation final audit（completed）

退出标准：

- Distribution Alpha 明确依赖 AgentCore 和 Security Execution Foundation final audit。
- 后续发行版任务必须安装并验证 `agentd`、policy pack、tool manifest、run-state、audit、rollback、ModelBroker config。
- 所有 Runtime Foundation tests、safety gates、release/provenance checks 通过。

## 必须先冻结的决策

1. 首发产品形态：**已冻结为 Developer VM first, Cloud VM compatible**，见 `docs/decisions/000-mvp-shape.md`。
2. MVP 运行假设：**已冻结为 x86_64 Linux VM、Debian/Ubuntu、single-tenant/single-operator、TUI-first、external LLM optional-only**，见 `docs/decisions/001-mvp-operating-assumptions.md`。
3. 外部 LLM 策略：**已冻结为 optional-only；local-only 或 stub planner mode 必须可运行**。
4. Scope control：**已锁定 MVP non-goals 与回流规则**，见 `docs/decisions/002-mvp-scope-control.md`。
5. 首个真实 Runbook：已收窄为 service recovery，具体 fixture 留给 Wave 1/Wave 4 决策。

对应任务：`.workflow/active/WFS-20260522-agentos-linux-mvp/.task/TASK-AIOS-000.json`

## MVP 波次

### Wave 0：产品与架构冻结

- `TASK-AIOS-000`：冻结 MVP 产品形态与运行假设（父任务，completed）
- `TASK-AIOS-000A`：选择 MVP 产品形态与首批 workflow（completed，commit `6a7e6ab`）
- `TASK-AIOS-000B`：冻结 MVP 运行假设（completed，commit `951241d`）
- `TASK-AIOS-000C`：锁定 MVP non-goals 与 scope change control（completed，commit `a68e3bd`）
- `TASK-AIOS-000D`：把 Wave 0 决策传播到 Wave 1 入口条件（completed，commit `7281c8e`）

退出标准：

- 首发形态、目标用户、环境和前三个 workflow 明确。
- `research.md` 中未指定假设已经接受、拒绝或推迟。
- MVP non-goals 写入决策文档。

### Wave 1：可启动控制面

- `TASK-AIOS-001`：创建最小 Linux boot image，并验证 `agentd` handoff（completed）
- `TASK-AIOS-002`：实现 `agentd` lifecycle skeleton（completed）
- `TASK-AIOS-003`：构建 terminal-first TUI intent / approval surface（completed）

Wave 1 入口约束：

- 目标形态是 Developer VM first，Cloud VM compatible。
- 目标环境是 `x86_64` Debian/Ubuntu-compatible Linux VM。
- Wave 1 验收不能依赖 Firecracker、外部 LLM、fleet orchestration 或 GUI。
- `agentd` 与 TUI 必须支持 local-only 或 stub planner mode。
- normal mode 不允许任意 root shell。

退出标准：

- 最小镜像可以启动到 `agentd` / TUI 路径。
- `agentd` 有健康状态、模块边界和可测试 lifecycle。
- 操作员可以输入 intent，并看到确定性 plan preview。

### Wave 2：语义运行时与审计

- `TASK-AIOS-004`：定义 semantic tool call schema 和 router（completed）
- `TASK-AIOS-005`：实现 append-only audit event journal（completed）
- `TASK-AIOS-006`：实现 unfinished effects recovery reconciler（completed）

退出标准：

- normal mode 没有泛化 `shell.exec`。
- 每个 effect 都先写 `EffectPrepared`，再执行。
- 重启后能识别 prepared、observed、sealed、rollback-pending 状态。

### Wave 3：Capability、sandbox 与 rollback

- `TASK-AIOS-007`：实现 capability lease model 和 policy evaluator（completed）
- `TASK-AIOS-008`：为 read-only / low-risk tools 增加 Linux sandbox executor（completed）
- `TASK-AIOS-009`：实现 `write-with-diff` 和 rollback handle flow（completed）

退出标准：

- capability 分为 `read-only`、`write-with-diff`、`execute-with-confirmation`、`privileged-with-human-approval`、`never`。
- read-only 工具受 namespace、cgroup、seccomp/no_new_privs、可选 Landlock 约束。
- 写操作先生成 diff 和 rollback handle，审批后才提交。

### Wave 4：真实 workflow 与质量门

- `TASK-AIOS-010`：实现第一个 service recovery workflow（completed）
- `TASK-AIOS-011`：加入 adversarial / safety regression tests（completed）
- `TASK-AIOS-012`：建立 MVP build、provenance 和 release artifact flow（completed）

退出标准：

- 至少一个真实恢复 workflow 可端到端运行。
- prompt injection、越权、资源滥用、rollback failure 进入 CI gate。
- 构建产物带基本 provenance / dependency inventory。

## MVP 不做

- 不做完整 Firecracker 产品化，只保留接口设计和 Alpha 任务入口。
- 不做多租户、HA、组织级策略治理。
- 不做 seL4/Genode 高安全版。
- 不做默认 GUI；GUI 只能作为 terminal 状态投影。
- 不做在线自改 `agentd`，升级策略留到 Beta 的 A/B rootfs。
- 不做 normal mode 下的任意 root shell。

新增或恢复任何 deferred item 前，必须先写 accepted decision，更新 `TASK.md`、`plan.json`、受影响 task JSON 和验证门，并单独 commit。

## 安全底线

- 默认 deny arbitrary shell。
- 高风险动作必须 human-in-the-loop。
- 外部网页、邮件、文档、API 响应默认 untrusted。
- secrets 只允许 handle-only，不进入模型上下文、长期记忆或普通日志。
- 审批 token 必须绑定 actor、tool、resource、parameter hash、expiry、policy version。
- 没有 audit 和 rollback 语义的自动写入功能不能上线。

## AgentOS Functional Iteration 任务计划

Source: `research.md`
Workflow: `.workflow/active/WFS-20260524-agentos-functional-iteration`  
Previous workflow: `.workflow/active/WFS-20260523-agentos-distribution-alpha`

目标：把 Distribution Alpha 从“可启动、可审计、可 promotion 的 runtime image path”，推进到“对操作员真正有用的 AgentOS 功能层”。这轮不追求更多自治，而是补齐真实 adapter、operator workflow、长期运行控制面和 functional release gate。

核心边界：

- `runtime_contracts` 定义稳定 request / response / report 类型。
- `agent_core` 负责编排 workflow、PlanRun、scheduler、observation、memory 和 projection 输入。
- `security_execution` 负责唯一 side-effect authority：policy、lease、sandbox、effect envelope、audit、rollback、source-to-sink。
- `agentd` 只负责 PID 1 lifecycle、CLI/TUI/API、operator projection 和 process integration。
- packaging / scripts 负责 rootfs artifact、fixture、smoke、release/provenance gate。

### Functional Iteration Wave 0：scope 与 capability matrix

- `TASK-FUNC-000`：冻结 functional iteration scope and capability matrix（completed）
- `TASK-FUNC-001`：定义 cross-crate capability contract ownership（completed）
- `TASK-FUNC-002`：定义 functional release gate and fixture strategy（completed）

退出标准：

- 用户可见能力映射到 owner module、runtime contract、semantic tool、policy、audit、rollback/fail-closed 和 release gate。
- 新功能不能只落在 `agentd` 里。
- baseline replay 不依赖 external LLM、network、Firecracker 或 host package manager。

### Functional Iteration Wave 1：真实 adapter contracts

- `TASK-FUNC-010`：扩展 package manager adapter contract and Debian fixture（completed）
- `TASK-FUNC-011`：扩展 untrusted content adapter contract and fetch fixture（completed）
- `TASK-FUNC-012`：扩展 Firecracker execution adapter contract and fail-closed fixture（completed）
- `TASK-FUNC-013`：增加 diagnostics and support bundle contract（completed）

退出标准：

- package、content、Firecracker、diagnostics/support bundle 都有 typed contract 和 fixture strategy。
- 可选宿主依赖缺失必须在 `EffectPrepared` 前 fail closed。
- fixture schema 可被最终 functional replay 复用。

### Functional Iteration Wave 2：workflow integration

- `TASK-FUNC-020`：把 package manager adapter 接入 AgentCore workflow（completed）
- `TASK-FUNC-021`：把 untrusted content adapter 接入 AgentCore workflow（completed）
- `TASK-FUNC-022`：把 Firecracker execution profile 接入 SecurityExecutionEngine（completed）
- `TASK-FUNC-023`：把 diagnostics/support bundle 接入 audit projection（completed）

退出标准：

- AgentCore 只负责编排，不直接执行 host mutation。
- SecurityExecution 仍是唯一 side-effect path。
- audit/operator projection 能解释 allowed、denied、paused、rollback 和 failed-closed 结果。

### Functional Iteration Wave 3：operator UX

- `TASK-FUNC-030`：增加 operator command registry and capability matrix projection（completed）
- `TASK-FUNC-031`：增加 approval、denial、rollback 和 audit command flows（completed）
- `TASK-FUNC-032`：增加 TUI capability workflow 和 support bundle export views（completed）

退出标准：

- 操作员能看到 AgentOS 当前能做什么、缺什么依赖、为什么被阻止。
- approval token 继续绑定 actor、tool、resource、parameter hash、expiry、policy version。
- TUI 是 runtime state projection，不是第二套 runtime。

### Functional Iteration Wave 4：long-running control plane

- `TASK-FUNC-040`：定义 persistent state migration and compatibility checks（completed）
- `TASK-FUNC-041`：增加 health、diagnostics 和 recovery drills（completed）
- `TASK-FUNC-042`：增加 audit retention、export 和 redaction gates（completed）
- `TASK-FUNC-043`：增加 update/rollback readiness hooks for production distro（completed）

退出标准：

- runtime state 有 versioned migration 和 compatibility gate。
- diagnostics/support bundle 不泄漏 secrets。
- update/rollback readiness 能作为 Production Distro 的入口条件。

### Functional Iteration Wave 5：functional promotion

- `TASK-FUNC-050`：构建 functional capability replay suite（completed）
- `TASK-FUNC-051`：把 functional replay 接入 release/provenance gate（completed）
- `TASK-FUNC-052`：运行 final functional audit 并决定下一步 production-distro gate（completed）

退出标准：

- `cargo test --workspace`、functional replay、release gate 通过或 blocker 明确。
- provenance 记录 capability matrix hash、fixture inventory hash 和 replay evidence hash。
- final audit 输出 `functional-ready`、`functional-remediation-required` 或 `rollout-blocked`。

## 下一步

Functional Iteration 已完成：typed contracts、AgentCore workflow bridge、SecurityExecution Firecracker fail-closed gate、operator command registry、support bundle projection、functional replay 和 release provenance gate 已落地。下一步进入 Production Distro 加固入口：以 functional replay、release gate、QEMU smoke、production signing verification 作为进入条件。

## Production Ecosystem Brainstorm

Source: 用户提出 AgentOS 未来可能需要类似 APT 的生态管理器，但它管理的对象不只是传统 package。  
Maestro brainstorm session: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem`

结论：AgentOS 需要 APT-like 的体验，但不能复制 APT-like 的信任模型。建议工作名为 `aom`，即 AgentOS Ecosystem Manager。它管理 AgentOS-native artifacts：capability pack、semantic tool pack、policy pack、workflow/runbook pack、model profile pack、knowledge pack、runtime adapter pack、execution image pack、test/replay pack 和 trust metadata。

核心不变量：

```text
install/stage != activate
```

`install/stage` 只代表 artifact 已经本地可用；`activate` 才会改变 runtime 行为。所有 activation 必须继续经过 Agent Core Runtime、SecurityExecutionEngine、audit、rollback 和 release/replay gate。底层 Debian/Ubuntu package manager 仍作为可选 adapter，不成为 `aom` 的第一目标。

关键产物：

- Guidance spec: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/guidance-specification.md`
- Feature index: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/feature-index.json`
- Synthesis: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/synthesis-specification.md`
- Roadmap: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/production-ecosystem-task-roadmap.md`
- Context report: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/context.md`

### Production Ecosystem Wave ECO-0：决策与对象模型

- `TASK-ECO-000`：冻结 ecosystem scope 和 `install is not activation` invariant（completed）
- `TASK-ECO-001`：定义 `runtime_contracts::ecosystem` module boundary（completed）
- `TASK-ECO-020`：定义 artifact coordinate 和 manifest schema（completed）
- `TASK-ECO-021`：定义 registry snapshot 和 lockfile schema（completed）
- `TASK-ECO-022`：定义 activation report 和 installed/active state schema（completed）
- `TASK-ECO-023`：定义 compatibility and migration validation（completed）
- `TASK-ECO-030`：定义 trust tier and channel policy（completed）

退出标准：

- Manifest、registry snapshot、lockfile 和 activation report 足够稳定，可被 fixture 和 replay 使用。
- 首批 artifact kinds 冻结为 `policy-pack`、`workflow-pack`、`test-replay-pack`。
- Policy invariant 明确：policy pack 不能削弱 core safety rules。

### Production Ecosystem Wave ECO-1：local registry 与 staging

- `TASK-ECO-002`：增加 local registry fixture 和 artifact resolver（completed）
- `TASK-ECO-003`：实现 staging store with digest/signature verification report（completed）
- `TASK-ECO-010`：定义 operator-facing artifact explanation format（completed）
- `TASK-ECO-011`：增加 `aom` CLI surface for local lifecycle（completed）
- `TASK-ECO-024`：增加 revocation/advisory metadata model（completed）
- `TASK-ECO-025`：增加 deterministic ecosystem hash projection for provenance（completed）

退出标准：

- `aom search/show/verify/stage/explain` 可以在 local fixture registry 上工作。
- Staged artifacts 是 inert state，不改变 runtime 行为。
- Digest mismatch、revoked artifact 和 incompatible schema fail closed。

当前完成度：

- `agentd --aom search/show/verify/stage/explain` 已可基于 rootfs local registry fixture 工作，`stage` 只写 inert staged artifact evidence，`activate` 仍明确 blocked 到 `TASK-ECO-004` / `TASK-ECO-005`。
- Operator projection 已增加只读 ecosystem 区块，显示 local registry、`aom.*` commands、activation gated、staged != active、无 shell、resolver owner 为 `agent_core::ecosystem`。
- Rootfs validator 已把 `aom.*` command registry 和 `ecosystem.registry_snapshot` 纳入 Alpha package defaults。
- Release provenance 已增加 deterministic ecosystem hash projection，记录 registry snapshot、lockfile、staged set、active set、replay，并声明 ecosystem replay gate 在 `TASK-VERIFY-041` 后成为硬门。

### Production Ecosystem Wave ECO-2：activation through runtime

- `TASK-ECO-004`：通过 AgentCore PlanSpec 实现 activation planning（planned）
- `TASK-ECO-005`：把 activation side effects 接入 SecurityExecutionEngine（planned）
- `TASK-ECO-006`：在 `agentd` 增加 read-only ecosystem projection（planned）
- `TASK-ECO-012`：打包 built-in production-safe policy pack（planned）
- `TASK-ECO-013`：打包 built-in service recovery workflow pack（planned）
- `TASK-ECO-014`：把 ecosystem status 加到 TUI/operator projection（planned）

退出标准：

- `aom activate` 生成 PlanSpec，并使用既有 approval / policy / effect / audit flow。
- Activation report 包含 audit range 和 rollback handle。
- `agentd` 只展示 active/staged/blocked artifacts，不拥有 resolver 逻辑。

### Production Ecosystem Wave ECO-3：safety、replay 与 release gate

- `TASK-ECO-040`：增加 ecosystem schema unit tests（planned）
- `TASK-ECO-041`：增加 local registry replay script（planned）
- `TASK-ECO-042`：增加 adversarial artifact pack fixtures（planned）
- `TASK-ECO-043`：增加 activation rollback drill（planned）
- `TASK-ECO-044`：增加 revocation and advisory replay（planned）
- `TASK-ECO-045`：把 ecosystem hashes 加入 release provenance（planned）
- `TASK-ECO-046`：增加 long-running active artifact recovery smoke（planned）

退出标准：

- Release gate 在 ecosystem replay skipped/failed 时阻塞。
- Provenance 记录 registry snapshot hash、lockfile hash 和 replay evidence hash。
- Adversarial fixtures 覆盖 shell bypass、policy weakening、memory poisoning、secret embedding 和 adapter bypass。

### Production Ecosystem Wave ECO-4：trust 与组织控制

- `TASK-ECO-015`：定义 verified/community/local-dev channel policy（planned）
- `TASK-ECO-031`：定义 signing and revocation requirements（planned）
- `TASK-ECO-032`：定义 no-maintainer-script activation rule（planned）
- `TASK-ECO-033`：定义 community artifact sandbox-only policy（planned）
- `TASK-ECO-034`：把 ecosystem state 加到 support bundle manifest（planned）
- `TASK-ECO-035`：定义 organization allowlist and denylist overlay（planned）

退出标准：

- Production Distro 可以 pin allowed channels 并拒绝 unsigned artifacts。
- Support bundle 能解释 active artifact set、trust tier、channel 和 hashes，且不包含 raw secrets。
- Community/local-dev artifacts 默认不能 production-promote。

### Production Ecosystem Wave ECO-5：model、knowledge、adapter 与 image packs

- `TASK-ECO-050`：定义 model profile pack schema and local/stub/remote optionality（planned）
- `TASK-ECO-051`：定义 knowledge pack schema with trust labels and memory quarantine（planned）
- `TASK-ECO-052`：增加 model/knowledge adversarial replay fixtures（planned）
- `TASK-ECO-060`：定义 runtime adapter pack schema（planned）
- `TASK-ECO-061`：定义 execution image pack schema for Firecracker/sandbox/update bundles（planned）
- `TASK-ECO-062`：增加 adapter/image optional dependency fail-closed replay（planned）

退出标准：

- Model 和 knowledge packs 不能泄漏 secrets 或污染 privileged memory。
- Adapter packs 不能绕过 SecurityExecutionEngine。
- Image packs 在 activation 前证明 provenance、compatibility 和 rollback rules。

## Agent Runtime + Ecosystem Chain

Source: 用户明确提出需要一条完整链路：扩充 AgentOS 生态，同时强化目前的 Agent Runtime，因为 AgentOS 是完全依靠 Agent 来运作的。  
Workflow: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain`  
Brainstorm seed: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem`

目标：把 `functional-ready` 的 AgentOS 推进为 Production Distro 的完整运行链路。这个链路把两件事绑定在一起：

- Agent Runtime 是 OS control plane，负责 boot、steady-state、degraded、recovery、update 和 operator projection。
- `aom` 是 AgentOS-native ecosystem manager，负责管理 capability / tool / policy / workflow / model / knowledge / adapter / image / replay / trust metadata artifacts。

核心边界：

```text
Linux handles deterministic reality.
Agent Runtime handles intention and operation.
aom install/stage is inert.
aom activate is AgentCore PlanSpec + SecurityExecutionEngine side effect.
```

关键产物：

- Workflow session: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/workflow-session.json`
- Plan: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/plan.json`
- Task dir: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/.task`
- Agent-operated OS chain: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/docs/agent-operated-os-chain.md`
- Runtime ecosystem architecture: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/docs/runtime-ecosystem-architecture.md`
- Production distro task chain: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/docs/production-distro-task-chain.md`
- Acceptance gates: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/docs/acceptance-gates.md`

### Chain Wave 0：冻结完整链路与不变量

- `TASK-CHAIN-000`：冻结 Agent-operated OS and ecosystem chain（completed）
- `TASK-CHAIN-001`：定义 AgentOS lifecycle control map（completed）
- `TASK-CHAIN-002`：定义 `aom` install/stage/activate invariant（completed）
- `TASK-CHAIN-003`：定义 chain acceptance gates and evidence model（completed）

退出标准：

- AgentOS lifecycle 明确覆盖 boot、steady-state、degraded、recovery、update。
- `install/stage != activate` 成为生态不变量。
- Production Distro gate 同时覆盖 runtime 和 ecosystem。

### Chain Wave 1：Agent Runtime OS control loops

- `TASK-ARUN-010`：定义 boot and steady-state Agent Runtime control loops（completed）
- `TASK-ARUN-011`：定义 observation fabric and operator event intake（completed）
- `TASK-ARUN-012`：定义 scheduler、quotas、backpressure and autonomous action budget（completed）
- `TASK-ARUN-013`：定义 degraded mode and local/stub fallback behavior（completed）

退出标准：

- AgentOS 不靠旁路脚本维持主运行链路。
- Observation 不能直接触发高风险 action。
- Scheduler 能限制 retry、并发、预算和 backpressure。
- 缺 external LLM / network / Firecracker / host package manager 时可解释降级。

### Chain Wave 2：durable Agent Runtime state

- `TASK-ARUN-020`：定义 durable OS run state reconciliation（completed）
- `TASK-ARUN-021`：定义 approval、escalation and interrupt survival（completed）
- `TASK-ARUN-022`：定义 OS memory governance and knowledge quarantine（completed）
- `TASK-ARUN-023`：定义 runtime recovery drills for PID 1 operation（completed）

退出标准：

- Recovery 权威来自 RunStore + AuditJournal + active artifact state，不来自 model replay。
- Approval token 重启后仍绑定 actor、tool、resource、parameter hash、expiry、policy version。
- Memory / knowledge 不可污染 privileged action。
- PID 1 恢复 drill 可生成支持证据。

### Chain Wave 3-5：aom ecosystem spine and activation

- Wave 3：`TASK-ECO-000`、`TASK-ECO-001`、`TASK-ECO-020`、`TASK-ECO-021`、`TASK-ECO-022`、`TASK-ECO-023`、`TASK-ECO-030`
- Wave 4：`TASK-ECO-002`、`TASK-ECO-003`、`TASK-ECO-010`、`TASK-ECO-011`、`TASK-ECO-024`、`TASK-ECO-025`
- Wave 5：`TASK-ECO-004`、`TASK-ECO-005`、`TASK-ECO-006`、`TASK-ECO-012`、`TASK-ECO-013`、`TASK-ECO-014`

退出标准：

- `runtime_contracts::ecosystem` 定义 artifact、registry、lockfile、activation report。
- `aom search/show/verify/stage/explain` 可在 local fixture registry 工作。
- `aom activate` 生成 AgentCore PlanSpec，并由 SecurityExecutionEngine 执行。

### Chain Wave 6-9：verification、trust、full ecosystem、Production Distro operations

- Wave 6：`TASK-VERIFY-040` 到 `TASK-VERIFY-044`
- Wave 7：`TASK-ECO-015`、`TASK-ECO-031`、`TASK-ECO-032`、`TASK-ECO-033`、`TASK-ECO-034`、`TASK-ECO-035`
- Wave 8：`TASK-ECO-050`、`TASK-ECO-051`、`TASK-ECO-052`、`TASK-ECO-060`、`TASK-ECO-061`、`TASK-ECO-062`
- Wave 9：`TASK-PROD-050`、`TASK-PROD-051`、`TASK-PROD-052`、`TASK-PROD-053`

退出标准：

- Ecosystem replay 和 adversarial fixtures 进入 release gate。
- Trust tiers、signing、revocation、organization overlay 可解释、可审计。
- Model/knowledge/adapter/image packs 不能泄漏 secrets、污染 memory 或绕过 SecurityExecutionEngine。
- Support bundle、A/B update readiness、offline snapshot drill 和 final chain audit 完成。

## AgentOS TUI Oriented System

Source: 用户要求继续迭代 TASK，让 AgentOS 变成 TUI-oriented system。  
Workflow: `.workflow/active/WFS-20260525-agentos-tui-oriented-system`  
Previous workflow: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain`

状态：completed。Final audit decision：`tui-oriented-alpha`。这不是 GA production-ready claim；production signatures、fleet rollout、remote registry governance 和长期运营运维仍是后续 Production Distro wave。

目标已完成：TUI 从 demo/projection surface 推进为 AgentOS 的主要 durable operator console。TUI 现在能驱动真实 AgentCore run、approval、denial、recovery、audit、support bundle 和 ecosystem activation preview，同时保持架构边界：TUI 是 projection-controller，不是第二套 runtime。

核心边界：

```text
TUI is the OS operator surface.
AgentCore owns PlanRun lifecycle.
SecurityExecutionEngine owns all side effects.
RunStore + AuditJournal + active artifact state are truth.
aom install/stage remains inert.
activation remains AgentCore PlanSpec + SecurityExecutionEngine.
```

关键产物：

- Workflow session: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/workflow-session.json`
- Plan: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/plan.json`
- Task dir: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/.task`
- TUI architecture: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/docs/tui-oriented-architecture.md`
- TUI task chain: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/docs/tui-oriented-task-chain.md`
- Final audit: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/evidence/FINAL-AUDIT-20260525-tui-oriented-agentos.json`
- Final summary: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/docs/final-tui-oriented-audit-summary.md`

已通过验证：

- `cargo fmt --check`
- `cargo test --workspace`
- `cargo test -p agentd tui_ --no-fail-fast`
- `cargo test -p agentd tui --no-fail-fast`
- `scripts/functional-capability-replay.ps1`
- `scripts/ecosystem-replay.ps1`
- `scripts/production-runbook-smoke.ps1`
- `scripts/tui-replay.ps1`
- `scripts/validate-alpha-rootfs.ps1`
- `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120`
- `scripts/boot-smoke-test.ps1 -SkipKernelDownload -KernelPath image\cache\vmlinuz-virt -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 120`

当前 TUI 能力：

- `--tui-interactive` 和 `--tui-scripted` 走 durable `TuiRuntimeController`。
- TUI controller 使用真实 `AgentCore<FileRunStore, DeterministicPlanner<StubModelProvider>>`。
- Typed command 支持 `dashboard.show`、`intent.submit`、`run.advance`、`run.approve`、`run.deny`、`run.suspend`、`run.recover`、`audit.show`、`support.bundle` 和 `aom.*`。
- `approvals.show latest` 渲染 exact approval binding：actor、tool、resource、parameter hash、policy version、expiry 和 deny hint。
- `recovery.show latest` 渲染 `source=run-store+audit-journal`、`no-model-replay=true`。
- `aom.activate.preview` 只做 activation preview，不因 install/stage 激活。
- Shell-like input、`shell.exec`、stage+activate chaining 和 secret-like input 均 fail closed / redacted。
- QEMU boot smoke 观察到 `AGENTOS_TUI_CONSOLE_READY`。

### TUI Wave 0：TUI OS Contract Freeze

- `TASK-TUI-000`：Freeze TUI-oriented AgentOS contract（completed）
- `TASK-TUI-001`：Define safe TUI command grammar（completed）
- `TASK-TUI-002`：Define TUI state and render model（completed）
- `TASK-TUI-003`：Define TUI replay and release gate strategy（completed）

### TUI Wave 1：Durable AgentCore TUI Bridge

- `TASK-TUI-010`：Add TuiRuntimeController over real AgentCore APIs（completed）
- `TASK-TUI-011`：Add durable TUI runtime path configuration（completed）
- `TASK-TUI-012`：Add approval、denial、suspend and recover handlers（completed）
- `TASK-TUI-013`：Add TUI controller lifecycle tests（completed）

### TUI Wave 2：Operator Console Views

- `TASK-TUI-020`：Build TUI dashboard from operator projection（completed）
- `TASK-TUI-021`：Build run detail and audit timeline view（completed）
- `TASK-TUI-022`：Build approval queue and blocked action view（completed）
- `TASK-TUI-023`：Build recovery、rollback and degraded state view（completed）
- `TASK-TUI-024`：Add TUI golden snapshot and redaction tests（completed）

### TUI Wave 3：Interactive Command Loop

- `TASK-TUI-030`：Replace demo interactive loop with safe typed command loop（completed）
- `TASK-TUI-031`：Add TUI command parser、help and explain errors（completed）
- `TASK-TUI-032`：Add deterministic TUI refresh and event model（completed）
- `TASK-TUI-033`：Add noninteractive scripted TUI mode for replay（completed）

### TUI Wave 4：Ecosystem And Production Operations In TUI

- `TASK-TUI-040`：Expose aom lifecycle projections in TUI（completed）
- `TASK-TUI-041`：Add activation preview view without stage activation（completed）
- `TASK-TUI-042`：Add support bundle export command and view（completed）
- `TASK-TUI-043`：Integrate TUI projection into production runbook smoke（completed）

### TUI Wave 5：Boot And Distro Packaging

- `TASK-TUI-050`：Add rootfs TUI console defaults（completed）
- `TASK-TUI-051`：Add TUI-ready boot marker and initramfs manifest fields（completed）
- `TASK-TUI-052`：Add QEMU TUI console smoke（completed）
- `TASK-TUI-053`：Preserve headless and automation compatibility（completed）

### TUI Wave 6：TUI Safety Replay And Final Audit

- `TASK-TUI-060`：Add local TUI replay script（completed）
- `TASK-TUI-061`：Add adversarial TUI command fixtures（completed）
- `TASK-TUI-062`：Gate release provenance on TUI replay（completed）
- `TASK-TUI-063`：Run final TUI-oriented AgentOS audit（completed）

后续 Production Distro 方向：

- Full-screen TUI shell：panes、navigation、command palette、live event stream。
- Operator session model：role-aware command scopes、sealed local profile state。
- Fleet/update operations：rollout rings、rollback drills、support bundle upload policy。
- Production signing：key ceremony、rotation、release decision evidence。
- Remote registry / marketplace governance：mirror、artifact review、organization policy overlays。

## AgentOS Console Beta And Production UX

Source: TUI-oriented Alpha final audit and post-Alpha Maestro brainstorm.  
Workflow: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux`  
Previous workflow: `.workflow/active/WFS-20260525-agentos-tui-oriented-system`

状态：completed。结论是 `console-beta`，不是 GA / Production Distro RC0。目标已经从 line-oriented typed TUI 推进到 full-screen-oriented Console Beta，并完成 Production Distro UX 铺设：Operations Workbench、Capability Catalog、Production Evidence Center、Fleet and Governance Preview。

核心判断：不要先疯狂加更多 runtime 功能。当前 AgentOS 底层能力已经足够多，下一轮要先让 operator shell 长期可用、可观察、可验证。

关键产物：

- Workflow session: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/workflow-session.json`
- Plan: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/plan.json`
- Task dir: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/.task`
- Final audit: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/evidence/FINAL-AUDIT-20260525-console-beta-production-ux.json`
- Final summary: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/docs/final-console-beta-audit-summary.md`
- Console architecture: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/docs/console-beta-architecture.md`
- Task chain: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/docs/console-beta-task-chain.md`
- Brainstorm: `.workflow/.csv-wave/20260525-brainstorm-agentos-tui-prod-next/context.md`

边界：

```text
TUI remains projection-controller only.
AgentCore owns PlanRun lifecycle.
SecurityExecutionEngine owns all side effects.
agent_core::ecosystem owns resolver and activation planning.
OperatorSession is UI state only, not permission authority.
ProjectionSnapshot is immutable render input, not source of truth.
```

### Console Beta Wave 0：Contract And Refactor Spine

- `TASK-TUI2-000`：Freeze Console Beta boundary and module ownership（completed）
- `TASK-TUI2-001`：Split TUI runtime into shell, parser, view model and dispatch modules（completed）
- `TASK-TUI2-002`：Add `ProjectionSnapshot` contract with source hashes（completed）

退出标准：

- TUI module ownership and shell boundaries are documented。
- Existing scripted and interactive commands still work。
- `ProjectionSnapshot` is defined as render input, not authority。

### Console Beta Wave 1：Full-Screen Operator Shell

- `TASK-TUI2-003`：Add full-screen pane layout model and narrow terminal fallback（completed）
- `TASK-TUI2-004`：Add command palette with contextual preview（completed）
- `TASK-TUI2-005`：Add full-screen layout snapshots and scripted parity gate（completed）
- `TASK-TUI2-006`：Add live event feed from durable audit/runtime projections（completed）

退出标准：

- Wide and narrow terminal layouts are stable。
- Command palette previews actions before dispatch。
- Event feed derives from durable projections。
- Scripted parity gate still passes。

### Console Beta Wave 2：Operations Workbench

- `TASK-TUI2-010`：Build Approval Center panel（completed）
- `TASK-TUI2-011`：Add approval binding diff and stale/expired token UX（completed）
- `TASK-TUI2-012`：Build Recovery Workbench panel（completed）
- `TASK-TUI2-013`：Add rollback consequence preview（completed）
- `TASK-TUI2-014`：Build Support Console panel（completed）
- `TASK-TUI2-015`：Add degraded-state explainer and evidence path actions（completed）

退出标准：

- Approval Center shows exact binding diff、expiry and denial path。
- Recovery Workbench shows recovery source、rollback needs and safe next action。
- Support Console exports redacted evidence and explains degraded state。

### Console Beta Wave 3：Capability Catalog

- `TASK-TUI2-020`：Add capability index projection（completed）
- `TASK-TUI2-021`：Add workflow catalog view（completed）
- `TASK-TUI2-022`：Add launch-intent preview for operational capabilities（completed）
- `TASK-TUI2-023`：Add AOM artifact detail and trust status panel（completed）
- `TASK-TUI2-024`：Add catalog replay gate（completed）

退出标准：

- Operational workflows are discoverable。
- Launching a capability creates an intent or preview only。
- Catalog and AOM views cannot directly execute or activate。

### Console Beta Wave 4：Production Evidence Center

- `TASK-TUI2-030`：Add release provenance panel（completed）
- `TASK-TUI2-031`：Add promotion blocker panel（completed）
- `TASK-TUI2-032`：Add local update and rollback drill view（completed）
- `TASK-TUI2-033`：Add QEMU/rootfs/replay gate status panel（completed）
- `TASK-TUI2-034`：Add candidate signing status view（completed）

退出标准：

- Release provenance、blockers and signing status are visible。
- QEMU/rootfs/replay gate status is projectable。
- Local update and rollback drill evidence is explainable。

### Console Beta Wave 5：Fleet And Governance Preview

- `TASK-TUI2-040`：Draft local-first fleet operations model（completed）
- `TASK-TUI2-041`：Add rollout ring projection prototype（completed）
- `TASK-TUI2-042`：Add support bundle upload policy design（completed）
- `TASK-TUI2-043`：Add remote registry mirror UX design（completed）
- `TASK-TUI2-044`：Add organization policy overlay preview（completed）
- `TASK-TUI2-050`：Run final Console Beta and Production UX audit（completed）

退出标准：

- Fleet and governance previews are explicit non-GA previews。
- Remote features are optional and fail closed。
- Final audit decided `console-beta` promotion；`production_ready_claim=false` remains intentional。

