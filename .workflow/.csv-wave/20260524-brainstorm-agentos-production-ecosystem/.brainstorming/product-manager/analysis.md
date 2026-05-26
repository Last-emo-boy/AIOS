# Product Manager Analysis

## Product Thesis

AgentOS 的生态不是“装软件”，而是让用户能安全地扩展 AgentOS 会做什么、能碰什么、怎么证明、怎么回滚。APT-like manager 的用户价值在于：

- 我可以发现 AgentOS 能力。
- 我可以理解安装某个能力会新增什么权限和风险。
- 我可以先本地验证，再激活。
- 我可以回滚，也能解释事故发生时哪些 artifact 生效。

## Ecosystem Participants

| Participant | Role |
| --- | --- |
| Core AgentOS team | 发布 core policy、official workflow、runtime adapters、release gates |
| Verified publisher | 发布经过签名和测试的 workflow / adapter / model profile / knowledge packs |
| Organization admin | 维护组织 trust roots、allowed channels、policy overlays |
| Operator | 搜索、安装、激活、禁用和回滚能力 |
| CI/release gate | 验证 artifact set 是否可推广到 Production Distro |

## Product Surfaces

Initial CLI/TUI commands:

- `aom search <query>`
- `aom show <artifact>`
- `aom fetch <artifact>`
- `aom verify <artifact>`
- `aom stage <artifact>`
- `aom activate <artifact>`
- `aom diff <artifact-set>`
- `aom rollback <activation-id>`
- `aom doctor`
- `aom explain blocked <artifact>`

Operator projection should answer:

- 这个能力来自哪个 publisher？
- 会新增哪些 tools/capabilities/policies/workflows？
- 是否需要网络、Firecracker、host package manager 或 remote model？
- baseline local replay 是否通过？
- 激活会不会改变 host state？
- rollback 句柄在哪里？

## Roadmap

### P0: Local-First Production Foundation

Ship a local fixture registry and built-in artifact kinds:

- `policy-pack`
- `workflow-pack`
- `test-pack`

This proves ecosystem mechanics without public marketplace risk.

### P1: Operational Capability Packs

Add useful built-in packs:

- production-safe policy pack
- service recovery workflow pack
- audit export workflow pack
- update readiness workflow pack
- support bundle replay pack

### P2: Adapter And Image Ecosystem

Add:

- package manager adapter pack
- content fetch adapter pack
- Firecracker profile/image pack
- cloud API adapter pack, still optional and disabled by default

### P3: Model And Knowledge Ecosystem

Add:

- local model profile pack
- organization knowledge pack
- vendor documentation pack
- workflow-specific retrieval pack

### P4: Community And Verified Channels

Only after local-first and core verified channel are stable:

- community channel
- publisher onboarding
- revocation/advisory feed
- organization policy portal

## Prioritization

The first shippable slice should be:

1. Artifact manifest and local registry.
2. `aom show/verify/stage/activate/rollback`.
3. Built-in production-safe policy pack.
4. Built-in service recovery workflow pack.
5. Ecosystem replay gate in release provenance.

This makes Production Distro more operational without requiring a public marketplace.

## Product Tasks

- `TASK-ECO-010`: Define operator-facing artifact explanation format.
- `TASK-ECO-011`: Add `aom` CLI surface for local registry lifecycle.
- `TASK-ECO-012`: Package built-in production-safe policy pack.
- `TASK-ECO-013`: Package built-in service recovery workflow pack.
- `TASK-ECO-014`: Add ecosystem status to TUI/operator projection.
- `TASK-ECO-015`: Define verified/community/local-dev channel policy.
