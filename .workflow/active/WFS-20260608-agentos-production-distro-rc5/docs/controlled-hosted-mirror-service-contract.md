# Controlled Hosted Mirror Service Contract

## Scope

RC5 starts from the RC4 final audit: hosted transport, remote registry mirror replay, fleet rollout smoke, rollback projection, support/recovery projection, and hosted/fleet promotion gates all pass locally, but RC4 does not prove a real hosted service or real multi-node canary.

RC5 introduces a controlled hosted mirror service framework at `aios.w33d.xyz`, backed by the operator-provided host `47.101.11.109`. The host is infrastructure for distribution metadata only. It is not a signing service, activation service, production ring controller, or general remote command plane.

The RC5 hosted mirror service may expose:

- Static health metadata at `/health.json`.
- Static service metadata at `/.well-known/aios/mirror.json`.
- Hash-bound channel metadata at `/channel/index.json`.
- Small release metadata and placeholder directories under `/releases/`.
- Optional support and recovery indexes under `/support/`, only if redacted and hash-bound.

The RC5 hosted mirror service may not expose:

- Private signing keys, local release authority paths, or signer tokens.
- A signing endpoint.
- A rollout or activation endpoint.
- Large release payload storage beyond placeholder or explicitly bounded canary metadata.
- Mutable active-slot state, production ring state, or remote shell dispatch.

## Remote Layout Contract

RC5-010 should provision a minimal, inspectable layout:

- Static mirror root: `/srv/aios-mirror`.
- Health file: `/srv/aios-mirror/health.json`.
- Service descriptor: `/srv/aios-mirror/.well-known/aios/mirror.json`.
- Channel index: `/srv/aios-mirror/channel/index.json`.
- Release metadata placeholder: `/srv/aios-mirror/releases/README.txt`.
- Nginx site config: distro-appropriate site file for `aios.w33d.xyz`.
- Logs: standard nginx access and error logs only.

The initial service should stay small enough for limited server storage. Until object storage or a larger mirror node exists, RC5 may publish only metadata, indexes, health files, and placeholder release descriptors.

## Authority Boundary

Hosted mirror transport is distribution evidence only. It cannot make a release trusted by itself.

Required authority rules:

- Signing remains external to the mirror. The mirror can host public signatures or signed metadata, but it cannot create signatures.
- Publication remains hash-bound to RC4/RC5 evidence and must be append-only or content-addressed.
- Activation remains an AgentCore PlanSpec and SecurityExecutionEngine side effect.
- Fleet rollout remains exact-operator-approval gated.
- Rollback requires a baseline and cannot be executed by nginx, static metadata, TUI, model replay, or remote shell reachability.
- User-facing installers or updaters must verify signatures, hashes, freshness, revocation, and rollback metadata before trusting the mirror.

## Endpoint Contract

`/health.json` must be small, public, cache-safe, and secret-free. It should include:

- `schema`
- `status`
- `service`
- `domain`
- `generated_at`
- `production_ready_claim=false`
- `storage_mode=metadata-only`
- `signing_authority=false`
- `activation_authority=false`

`/.well-known/aios/mirror.json` should explain the service role:

- Mirror root and endpoint version.
- RC5 workflow id.
- Storage limit policy.
- Allowed paths.
- Disallowed authority.
- Freshness policy.

`/channel/index.json` should be hash-bound and non-GA:

- `schema`
- `channel`
- `status`
- `production_ready_claim=false`
- `source_rc4_final_audit_sha256`
- `hosted_transport_manifest_sha256`
- `mirror_publication_sha256`
- `freshness_window`
- `entries`

## Fail-Closed Requirements

RC5 tasks must fail closed for:

- DNS resolves but `/health.json` is missing or malformed.
- HTTP works but TLS is absent when a GA claim is attempted.
- Channel metadata is missing `production_ready_claim=false`.
- Channel metadata lacks RC4 final audit or RC4 hosted transport hash binding.
- Metadata freshness exceeds the declared window.
- Metadata contains private key markers, signer tokens, local private authority paths, or host-local absolute paths.
- Metadata points at large artifacts before storage policy is upgraded.
- Metadata advertises signing, activation, rollback execution, active-slot mutation, production ring mutation, or TUI authority.
- Nginx serves directory listing for mirror internals.
- Remote service state diverges from local evidence without a new publication evidence task.

## Completion Criteria

RC5-001 is complete when this contract exists, the RC5 workflow plan is active, the evidence file records RC4 hash bindings and RC5 non-GA boundaries, and the next executable task is `RC5-002`.
