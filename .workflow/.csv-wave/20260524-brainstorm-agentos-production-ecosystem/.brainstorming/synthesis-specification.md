# AgentOS Production Ecosystem Synthesis

## Core Design

AgentOS should introduce an APT-like manager named `aom`, but its package unit is not a Linux package. Its package unit is an AgentOS artifact:

- capability pack
- semantic tool pack
- policy pack
- workflow/runbook pack
- model profile pack
- knowledge pack
- runtime adapter pack
- execution image pack
- test/replay pack
- trust metadata pack

The manager owns artifact lifecycle. It does not own runtime authority. Runtime authority remains with the existing Agent Core Runtime and Security Execution Foundation.

## Lifecycle

```text
search -> show -> fetch -> verify -> stage -> diff -> plan activation
  -> approve -> activate -> observe -> seal -> rollback/deactivate
```

The crucial invariant is:

```text
install/stage != activate
```

## Production Distro First Slice

The next Production Distro iteration should implement the local-first ecosystem foundation:

1. `runtime_contracts::ecosystem` schemas.
2. Local registry fixture under packaging.
3. Artifact resolver and staging report.
4. Activation PlanSpec bridge in `agent_core`.
5. Activation effect path in `security_execution`.
6. Operator projection in `agentd`.
7. Ecosystem replay script and release provenance hashes.
8. Built-in `policy-pack`, `workflow-pack`, `test-pack` samples.

This gives AgentOS an ecosystem spine without needing a remote marketplace.

## Future Ecosystem

After the local-first foundation:

- verified publisher channel
- organization policy overlays
- revocation/advisory feed
- runtime adapter packs
- Firecracker image packs
- model profile packs
- knowledge packs
- public community channel
- ecosystem compatibility dashboard

## Production Risks

- A package ecosystem can become a policy bypass surface.
- Community workflows can smuggle shell execution.
- Knowledge packs can poison memory.
- Model profiles can leak secrets if not handle-only.
- Adapter packs can become backdoor side-effect paths.
- Registry freshness and revocation failures can leave bad artifacts active.

Every one of these risks must become replay/adversarial fixtures before Production Distro promotion.
