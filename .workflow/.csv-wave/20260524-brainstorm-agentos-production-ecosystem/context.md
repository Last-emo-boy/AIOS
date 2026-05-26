# Brainstorm Report -- AgentOS Production Ecosystem

## Summary

- Topic: AgentOS Production Distro complete ecosystem and APT-like manager.
- Decision: `ecosystem-brainstorm-ready`
- Roles analyzed: guidance-generator, system-architect, product-manager, data-architect, subject-matter-expert, test-strategist, synthesis.
- Feature count: 8.
- Roadmap: 6 waves, `TASK-ECO-000` through `TASK-ECO-062` with gaps reserved for future expansion.

## Core Conclusion

AgentOS does need an APT-like manager, but its unit of management should not be a traditional OS package. The manager should be AgentOS-native and manage capability packs, semantic tool packs, policy packs, workflow packs, model profile packs, knowledge packs, runtime adapter packs, execution image packs, test/replay packs and trust metadata.

Working name: `aom`，AgentOS Ecosystem Manager。

Key invariant:

```text
install/stage != activate
```

Install/stage only makes an artifact locally available. Activation changes runtime behavior and must go through Agent Core Runtime, SecurityExecutionEngine, audit, rollback and release/replay gates.

## Feature Index

See `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/feature-index.json`.

Features:

- `F-001`: Artifact manifest and registry object model.
- `F-002`: Local-first ecosystem manager.
- `F-003`: Capability, tool and policy pack system.
- `F-004`: Workflow and runbook pack system.
- `F-005`: Model profile and knowledge pack governance.
- `F-006`: Runtime adapter and execution image packs.
- `F-007`: Trust, channel and supply-chain control plane.
- `F-008`: Ecosystem replay, compatibility and production promotion.

## Recommended Next Slice

Start with ECO-0 and ECO-1:

1. `runtime_contracts::ecosystem` schema.
2. Local registry fixture.
3. Artifact coordinate, manifest, snapshot and lockfile.
4. `aom show/verify/stage/explain`.
5. Staging store with deterministic hash report.
6. Release provenance hash projection.

Activation should start only after the schema and local staging model are stable.

## Key Artifacts

- Guidance: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/guidance-specification.md`
- Synthesis: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/synthesis-specification.md`
- Feature index: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/feature-index.json`
- Roadmap: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/production-ecosystem-task-roadmap.md`
- Changelog: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/synthesis-changelog.md`

## Next Step

Promote the roadmap into a new active workflow, likely:

```text
.workflow/active/WFS-20260524-agentos-production-ecosystem-foundation
```

The implementation should begin with schema and local registry, not public marketplace or real remote registry hosting.
