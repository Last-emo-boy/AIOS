# AgentOS Production Ecosystem Guidance Specification

Topic: AgentOS Production Distro complete ecosystem and APT-like manager for capabilities, tools, policies, models, workflows, adapters, images and trust metadata.

Session: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem`

## Positioning

AgentOS 的生态层不应复制传统 Linux package manager 的边界。APT 管理的是 binary package、dependency、repository、signature 和 installed state；AgentOS 需要管理的是更高层的可执行自治边界：capability、semantic tool、policy、workflow、model profile、runtime adapter、guest image、test pack、trust metadata 和它们的 activation evidence。

建议暂名为 **AgentOS Ecosystem Manager**，简称 `aom`。它不是 `apt` 的替代品，而是 AgentOS-native artifact manager。底层 Debian/Ubuntu package 仍由 host package adapter 包装，且任何 host mutation 仍必须经过 existing package install workflow、isolated validation、exact approval、rollback binding 和 SecurityExecutionEngine。

## Core Terms

- **AgentOS Artifact**：可安装、可验证、可激活、可回滚的 AgentOS-native 对象，不等同于传统 OS package。
- **Artifact Manifest**：描述 artifact identity、kind、version、dependencies、compatibility、trust metadata、activation hooks、replay gates 和 rollback semantics 的稳定 schema。
- **Capability Pack**：声明新的 capability 语义、risk class、lease constraints 和 explain text；它 MUST NOT 直接授予权限。
- **Semantic Tool Pack**：提供 tool schema、adapter contract、risk classification、fixture 和 sandbox expectation；它 MUST NOT 暴露 normal-mode arbitrary shell。
- **Policy Pack**：提供可版本化策略、approval requirements、source-to-sink rule、redaction rule 和 precedence metadata；它 MAY narrow baseline policy，但 MUST NOT disable safety invariants。
- **Workflow Pack**：提供 PlanSpec template、runbook、operator prompt、acceptance check 和 replay fixture；它只能通过 Agent Core Runtime 编排。
- **Model Profile Pack**：描述 local/remote/stub model provider、routing policy、allowed use、eval evidence 和 secret handling；它 MUST NOT embed production secrets。
- **Knowledge Pack**：提供文档索引、domain glossary、retrieval metadata 和 trust labels；它 MUST NOT write untrusted instructions into privileged memory.
- **Runtime Adapter Pack**：接入 package manager、service manager、cloud API、content fetcher、browser 或 VM runtime 的 typed adapter；所有 side effect MUST go through SecurityExecutionEngine。
- **Image Pack**：管理 Firecracker guest image、sandbox rootfs、kernel/initramfs slot 或 A/B update bundle；激活前 MUST verify provenance and compatibility。
- **Test/Replay Pack**：为 artifact 或 artifact set 提供 local-only replay、adversarial fixtures、compatibility checks 和 promotion gates。
- **Trust Metadata**：签名、provenance、SBOM、dependency inventory、revocation、vulnerability advisory、publisher identity 和 channel policy。

## Hard Boundaries

- `agentd` MUST remain thin：PID 1 lifecycle、CLI/TUI/API、operator projection、process integration。
- Ecosystem logic MUST flow through `runtime_contracts -> agent_core -> security_execution -> agentd projection -> release gate`。
- Normal mode MUST NOT expose arbitrary shell execution。
- External LLM、network、Firecracker、host package manager MUST NOT be baseline acceptance dependencies。
- Artifact install MUST be separate from artifact activation。
- Activation MUST be auditable, replayable, policy-checked and rollback-aware。
- Capability Pack MUST declare capability semantics only；actual lease grant remains runtime/policy decision。
- Policy Pack MUST NOT remove core invariants such as no raw secret logging, exact approval binding and untrusted source-to-sink denial。
- Workflow Pack MUST NOT directly mutate host state；it produces runtime plans and replay evidence。
- Community artifacts MUST default to sandbox-only activation until verified by stricter trust tiers。

## Non-Goals

- Do not replace Debian/Ubuntu package management in the first ecosystem wave。
- Do not create a marketplace that bypasses release/provenance gates。
- Do not let plugin authors write arbitrary `agentd` code paths。
- Do not allow artifact install to imply policy approval。
- Do not require remote registry access for local replay or release gate。
- Do not use model judgment as a trust decision for artifact activation。
- Do not make `agentd` own package resolution, policy merge, adapter business logic or test execution.

## Feature Decomposition

### F-001: Artifact Manifest And Registry Object Model

Priority: P0

Related roles: system-architect, data-architect, subject-matter-expert, test-strategist

Define `AgentOsArtifactManifestV1` and registry index schemas for capability, tool, policy, workflow, model profile, knowledge, adapter, image and replay artifacts. The schema MUST include identity, version, kind, compatibility, dependencies, trust metadata, activation requirements, rollback model and required replay gates.

### F-002: Local-First Ecosystem Manager

Priority: P0

Related roles: system-architect, product-manager, test-strategist

Build an offline-capable `aom` manager with `search`, `fetch`, `verify`, `stage`, `diff`, `activate`, `deactivate`, `rollback`, `explain` and `doctor` flows. Baseline MUST work against local fixture registries and MUST NOT require network.

### F-003: Capability, Tool And Policy Pack System

Priority: P0

Related roles: system-architect, subject-matter-expert, test-strategist

Create first-class pack types for capability semantics, semantic tools and policy. These packs SHOULD compose, but policy precedence MUST preserve baseline safety invariants and exact approval binding.

### F-004: Workflow And Runbook Pack System

Priority: P1

Related roles: product-manager, system-architect, test-strategist

Provide installable service recovery, package validation, untrusted content inspection, audit export and update readiness workflows. Workflow packs MUST compile into Agent Core Runtime plans and replay fixtures, not ad hoc `agentd` logic.

### F-005: Model Profile And Knowledge Pack Governance

Priority: P1

Related roles: product-manager, data-architect, subject-matter-expert

Manage model routing profiles, local model metadata, remote model optionality, retrieval indexes and domain knowledge packs. These artifacts MUST preserve secret-handle-only rules, memory quarantine and source trust labels.

### F-006: Runtime Adapter And Execution Image Packs

Priority: P1

Related roles: system-architect, data-architect, test-strategist

Package host adapters, Firecracker profiles, sandbox rootfs, guest images and update image bundles as typed artifacts. Missing optional dependencies MUST fail closed before `EffectPrepared`.

### F-007: Trust, Channel And Supply-Chain Control Plane

Priority: P0

Related roles: subject-matter-expert, data-architect, test-strategist

Define core, verified, community and local-dev trust tiers; stable, beta, edge and local channels; signed metadata; provenance; SBOM; revocation; vulnerability advisory and compatibility policy. Production Distro promotion MUST record ecosystem gate hashes.

### F-008: Ecosystem Replay, Compatibility And Production Promotion

Priority: P0

Related roles: test-strategist, system-architect, product-manager

Extend functional replay into ecosystem replay: artifact resolution, staging, activation simulation, policy merge, source-to-sink abuse, rollback, revocation and long-running soak. Release provenance MUST include registry snapshot hash, artifact manifest hashes and replay evidence hash.

## Suggested Initial Product Slice

The first Production Distro ecosystem slice SHOULD be local-first:

1. Define manifest and registry fixture schemas。
2. Implement local registry resolution and staging。
3. Support three starter artifact kinds: `policy-pack`, `workflow-pack`, `test-pack`。
4. Add one starter workflow pack: service recovery runbook。
5. Add one starter policy pack: production-safe baseline。
6. Add one starter replay pack: ecosystem activation replay。
7. Gate release provenance on ecosystem replay。

This slice proves the ecosystem model without depending on public registry hosting, community packages, real remote updates or external LLM access.
