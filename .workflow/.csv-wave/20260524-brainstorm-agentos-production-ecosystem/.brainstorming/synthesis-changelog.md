# Synthesis Changelog

## Summary

Decision: `ecosystem-brainstorm-ready`

The brainstorm converged on one core architecture decision: AgentOS needs an APT-like UX, but not an APT-like trust model. The ecosystem manager should manage AgentOS-native artifacts and separate `install/stage` from `activate`.

## Consensus

- `aom` should be local-first for the first Production Distro slice.
- Artifact installation MUST NOT imply runtime authority.
- Activation MUST pass through Agent Core Runtime and SecurityExecutionEngine.
- `agentd` should expose projection and commands, not own ecosystem business logic.
- The first artifact kinds should be `policy-pack`, `workflow-pack` and `test-pack`.
- Public/community marketplace should be delayed until core and verified channels are stable.
- Release provenance should include ecosystem lockfile, registry snapshot and replay result hashes.

## Resolved Conflicts

- [RESOLVED] **APT replacement vs AgentOS-native manager**：Use APT only as UX analogy. Host package mutation remains an adapter-backed workflow, while `aom` manages AgentOS-native artifacts.
- [RESOLVED] **Install vs activate**：Install/stage is inert. Activation is the controlled side-effect boundary.
- [RESOLVED] **Community ecosystem timing**：Defer public community channel. Start with local fixture, core and verified artifacts.
- [RESOLVED] **Policy pack power**：Policy packs may narrow behavior but must not remove baseline invariants.

## Suggested Decisions To Freeze Next

1. Accept `aom` as the working name for AgentOS Ecosystem Manager.
2. Accept artifact coordinate format `agentos:<kind>/<publisher>/<name>@<version>`.
3. Accept `policy-pack`, `workflow-pack`, `test-pack` as the first three artifact kinds.
4. Accept `install is not activation` as a Production Distro invariant.
5. Accept local registry fixture as the first implementation target.

## Confidence

- role coverage: high
- cross-role consistency: high
- feature completeness: medium-high
- spec quality: high for planning, medium for implementation detail
- design feasibility: high for local-first slice, medium for public registry/community channel

No unresolved conflict blocks planning.
