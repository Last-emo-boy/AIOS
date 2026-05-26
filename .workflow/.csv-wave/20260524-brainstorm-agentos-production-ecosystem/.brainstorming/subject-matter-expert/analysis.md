# Subject Matter Expert Analysis

## Domain Thesis

APT is a useful analogy for UX, not for authority. APT assumes packages are allowed to run maintainer scripts and mutate system state as part of installation. AgentOS cannot copy that model because an AgentOS artifact may expand autonomous behavior. The safe primitive is:

```text
fetch -> verify -> stage -> replay -> diff -> approve -> activate -> audit -> rollback
```

Installation must never equal trust.

## What AgentOS Should Manage

AgentOS ecosystem manager should manage:

- capabilities: what a runtime can ask for
- tools: typed semantic tool schemas and adapters
- policies: evaluation rules and approval requirements
- workflows: reusable runbooks compiled into AgentCore plans
- models: routing profiles, local model metadata, optional remote model policy
- knowledge: trusted retrieval packs and domain docs
- adapters: host package manager, service manager, cloud APIs, content fetchers
- images: sandbox rootfs, Firecracker guest image, update slots
- tests: replay, adversarial and compatibility packs
- trust metadata: signatures, provenance, SBOM, revocation, advisories

## Trust Tiers

Recommended trust tiers:

- `core`: shipped with AgentOS release and covered by release gate.
- `verified`: signed publisher, verified channel, required replay evidence.
- `organization`: locally approved artifact set, may override channel policy narrowly.
- `community`: discoverable but sandbox-only by default.
- `local-dev`: explicit developer mode, never production promotable by default.

## Signing Requirements

Must be signed:

- registry snapshots
- artifact manifests
- content archives
- policy packs
- model profile packs
- runtime adapter packs
- image packs
- release lockfiles
- revocation/advisory metadata

May be unsigned only in local-dev:

- scratch workflow packs
- local knowledge packs
- experimental test packs

Unsigned artifacts MUST NOT be activated in Production Distro.

## Safety Constraints

- Maintainer scripts should not exist in the APT sense. Activation hooks must be typed semantic operations.
- Policy packs cannot disable core safety invariants.
- Workflow packs cannot include shell snippets as execution authority.
- Model profiles cannot store secrets.
- Knowledge packs must carry trust labels and cannot auto-promote untrusted instructions into memory.
- Adapter packs must prove fail-closed behavior for missing dependencies.

## Production Distro Implications

Production Distro should ship with:

- pinned core registry snapshot
- offline activation of core artifacts
- verified update metadata
- revocation checking
- ecosystem replay gate
- operator explainability for every active artifact
- support bundle section for ecosystem state

## SME Tasks

- `TASK-ECO-030`: Define trust tier and channel policy.
- `TASK-ECO-031`: Define signing and revocation requirements.
- `TASK-ECO-032`: Define no-maintainer-script activation rule.
- `TASK-ECO-033`: Define community artifact sandbox-only policy.
- `TASK-ECO-034`: Add ecosystem state to support bundle manifest.
- `TASK-ECO-035`: Define organization allowlist and denylist overlay.
