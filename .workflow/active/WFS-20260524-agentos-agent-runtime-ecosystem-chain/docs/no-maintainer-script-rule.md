# No Maintainer Script Rule

## Purpose

AgentOS artifacts must not inherit the traditional package-manager model where install or activation scripts run with ambient host authority. Artifact activation is a typed runtime operation.

## Forbidden

Artifact manifests cannot define:

- arbitrary shell hooks
- preinstall, postinstall, prerm or postrm scripts
- raw `apt`, `dpkg`, `rpm`, `pacman` or package-manager command fragments
- direct host mutation outside SecurityExecutionEngine
- model-provided executable scripts
- activation side effects during stage

## Required Activation Shape

Activation must compile into typed semantic operations:

- `ecosystem.replay.verify`
- `ecosystem.compatibility.check`
- `ecosystem.activate`
- rollback metadata preparation
- audit sealing

`aom activate` produces a previewable AgentCore PlanSpec. SecurityExecutionEngine owns policy evaluation, exact approval, sandbox profile selection, EffectPrepared and CommitSealed.

## Package Adapter Boundary

Package-manager adapters are different from AgentOS ecosystem activation. They remain isolated workflows with semantic package tools, exact approval and rollback. Adapter metadata cannot become maintainer-script authority and cannot mutate host state before policy approval.

## Failure Behavior

If an artifact needs a raw script to activate, it is incompatible with Production Distro. The correct path is to add a typed semantic operation and a SecurityExecution policy gate, then cover it with replay and rollback evidence.
