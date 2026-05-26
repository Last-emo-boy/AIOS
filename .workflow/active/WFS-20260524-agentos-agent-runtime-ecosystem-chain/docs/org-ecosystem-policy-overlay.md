# Organization Ecosystem Policy Overlay

## Purpose

Organization overlays let operators govern artifact activation for their environment without bypassing AgentOS baseline invariants.

## Overlay Schema

An organization overlay should include:

- overlay id
- organization id
- policy owner
- allowlist coordinates or publisher scopes
- denylist coordinates, publishers or advisory ids
- allowed channels
- max trust tier allowed for activation
- required approvals
- expiration
- policy diff hash

## Precedence

Denylist wins over allowlist. Revocation wins over allowlist. Baseline AgentOS invariants win over every organization rule.

An allowlist can narrow or approve an already valid path. It cannot enable normal shell, disable exact approval, bypass source-to-sink checks, expose raw secrets, remove audit or remove rollback.

## Activation Flow

Organization overlay decisions are evaluated before activation PlanSpec execution. The operator must see:

- which artifact is allowed or denied
- which overlay rule matched
- whether the decision narrows or extends behavior
- the policy diff hash
- required approval and rollback metadata

## Audit And Support

Every overlay decision must be audit/projectable and visible in support bundles without private key paths or raw secret values.

## Failure Behavior

If overlay metadata is malformed, expired, unsigned when required or attempts to weaken a baseline invariant, activation fails closed before EffectPrepared.
