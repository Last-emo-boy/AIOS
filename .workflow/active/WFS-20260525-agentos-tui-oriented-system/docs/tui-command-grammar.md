# TUI Command Grammar

This document freezes the first production TUI command contract for AgentOS.

The TUI accepts semantic operator commands, not shell fragments. A command string is parsed into a typed operation and then dispatched to the subsystem that already owns the behavior.

## Command Classes

Runtime commands:

- `intent.submit <text>`
- `run.plan <run-id>`
- `run.advance <run-id>`
- `run.approve <run-id> <step-id> actor=<actor>`
- `run.deny <run-id> <step-id> actor=<actor> reason=<text>`
- `run.suspend <run-id> reason=<text>`
- `run.recover <run-id>`
- `run.show <run-id|latest>`

Projection commands:

- `dashboard.show`
- `audit.show <run-id|latest>`
- `support.bundle status`
- `support.bundle export`

Ecosystem commands:

- `aom.search [query]`
- `aom.show <coordinate>`
- `aom.verify <coordinate>`
- `aom.stage <coordinate>`
- `aom.explain <coordinate>`
- `aom.activate.preview <coordinate>`

Session commands:

- `help`
- `refresh`
- `exit`

## Owners

- `AgentCore` owns `intent.submit`, `run.plan`, `run.advance`, `run.approve`, `run.deny`, `run.suspend` and `run.recover`.
- `RunStore` and `AuditJournal` are the durable truth for `run.show` and `audit.show`.
- `agentd` owns TUI parsing, rendering and read-only operator projection.
- `agent_core::ecosystem` owns ecosystem resolver and activation planning.
- `SecurityExecutionEngine` owns policy, approval validation, side effects, audit sealing and rollback.

## Rejected Input

The parser must fail closed for shell-like syntax:

- pipes: `|`
- redirection: `>`, `<`, `>>`, `2>`
- command chaining: `;`, `&&`, `||`
- command substitution: `$(`, backticks
- host shell names as commands: `sh`, `bash`, `cmd`, `powershell`, `pwsh`
- unknown commands

Rejected input is never dispatched to a host shell. The TUI returns a typed parse error and a safe help hint.

## Approval Semantics

Approval commands require exact identity:

- run id,
- step id,
- actor,
- policy-generated parameter hash inside AgentCore/SecurityExecution state.

The TUI never constructs a broad approval. It only asks AgentCore to bind the exact approval token for the current durable step.

## Ecosystem Activation

`aom.search`, `aom.show`, `aom.verify`, `aom.stage` and `aom.explain` are projections or inert local lifecycle operations.

`aom.activate.preview` can show a planned activation path, but active artifact mutation must be a real AgentCore PlanSpec executed through SecurityExecutionEngine. `install` and `stage` do not activate.
