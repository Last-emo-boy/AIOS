# UX Expert Analysis

## Operator Journey

The primary journey should be:

1. Boot into AgentOS console.
2. See system health and current attention items.
3. Inspect active or recoverable runs.
4. Submit an intent or select a capability.
5. Review plan preview.
6. Approve, deny or recover with exact context.
7. Export support evidence if needed.

The current typed commands prove the backend is viable. The experience now needs navigation, memory and discoverability.

## Information Architecture

Top-level sections:

- Dashboard
- Runs
- Approvals
- Recovery
- Capabilities
- Ecosystem
- Support
- Release

Persistent global elements:

- status bar: mode, source freshness, local-only status, degraded count
- command palette: typed commands and contextual actions
- event feed: latest audit/projection events
- attention rail: pending approvals, rollback required, degraded artifacts

## Command Ergonomics

The command palette should support:

- fuzzy search over typed commands
- context-aware completion
- preview before dispatch
- exact binding display for approvals
- refusal explanations for unsafe commands
- history search
- one-key copy of support bundle path or evidence id

No shortcut should bypass preview for high-risk actions.

## Recovery UX

Recovery should not be a passive report. It should answer:

- What happened?
- What source proves it?
- What is safe to verify?
- What needs rollback?
- What needs human review?
- What command is safe next?

Use progressive disclosure: summary first, audit evidence second, raw hashes last.

## Onboarding

The first-run screen should not be marketing. It should be a working dashboard with empty states:

- no active runs
- no pending approvals
- local-only model broker active
- support bundle ready
- available capabilities

Empty states should show commands, not explanations of product features.

## UX Risks

- Showing too much audit detail by default will bury urgent actions.
- Hiding source hashes entirely will reduce trust for production operators.
- Command aliases can become dangerous if they obscure exact binding.
- Role-aware scopes must be presented as UX constraints, not security authority.

## Recommendation

Build an attention-first console. The first viewport should answer what needs action now. Everything else should be one navigation step away.
