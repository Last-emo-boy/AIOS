# Community Artifact Policy

## Purpose

Community artifacts should be discoverable without becoming trusted Production Distro behavior by default. Discovery and staging are not activation.

## Default Restrictions

Community artifacts:

- are not production-promotable by default
- are sandbox-only by default
- cannot broaden host authority
- cannot provide privileged runtime adapters
- cannot access raw secrets
- cannot weaken policy packs
- cannot mutate active artifact state

Schema and digest verification may allow local inspection or inert staging. Activation remains blocked unless a later promotion workflow upgrades the artifact into verified or organization trust.

## Promotion Requirements

Promotion from community requires:

- signed manifest and payload
- verified publisher or organization allowlist
- replay evidence
- compatibility evidence
- revocation metadata
- policy diff review
- rollback handle
- audit-visible approval

Community artifacts cannot skip directly to core.

## Operator Projection

Operator projection and support bundles must show community risk clearly: trust tier, channel, non-promotable default, sandbox-only status and required promotion gates.

## Failure Behavior

If a community artifact attempts direct host mutation, secret access, shell execution, policy weakening or self-granted capabilities, replay must deny before EffectPrepared and produce audit/projectable evidence.
