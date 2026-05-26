# TUI Oriented Task Chain

Goal: make AgentOS feel like a TUI-first operating system while preserving the architecture that makes it safe.

## Current Gap

Current TUI status is a demo/projection surface:

- `--tui-demo` renders a stub plan and synthetic audit events.
- `--tui-interactive` accepts an intent but builds a suspended demo session.
- `--operator-project-tui` renders real read-only projection text.

The missing part is a durable TUI controller over real `AgentCore` runs.

## Target

The operator should boot into, or launch, a TUI console that can:

- submit intent,
- create and freeze plans,
- advance read-only steps,
- pause on high-risk steps,
- approve or deny exact gated actions,
- recover interrupted runs,
- inspect audit and support bundles,
- inspect and preview ecosystem actions,
- explain why something is blocked or degraded.

## Wave Summary

- Wave 0 freezes the TUI OS contract.
- Wave 1 connects TUI to durable AgentCore run APIs.
- Wave 2 builds deterministic operator views.
- Wave 3 adds the safe interactive command loop.
- Wave 4 exposes ecosystem and production operations through TUI.
- Wave 5 makes the TUI console part of distro packaging and boot proof.
- Wave 6 adds replay, adversarial tests, release gate and final audit.

## Hard Boundaries

- No arbitrary shell.
- No direct model-to-tool execution.
- No TUI-owned side effects.
- No TUI-owned registry resolver.
- No TUI state as source of truth.
- No activation by install or stage.
