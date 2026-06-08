# TLS Storage And Signed Payload Threat Model

## Scope

RC6 expands the hosted AIOS mirror from RC5 metadata into an installable payload metadata surface. The mirror is still transport. It is not a root of trust, a signing service, an installer, a rollback controller, or a fleet authority.

This threat model covers:

- HTTP/TLS and DNS binding for `aios.w33d.xyz`.
- Static Nginx hosting under `/srv/aios-mirror`.
- Bounded metadata storage for `/payloads/` and `/install/`.
- Signed payload metadata semantics.
- Frontend UX risks where visibility could be misread as install readiness.

## Trust Boundary

The hosted service may serve static public files:

- `/`
- `/assets/*`
- `/health.json`
- `/.well-known/aios/mirror.json`
- `/channel/index.json`
- `/bootstrap/manifest.json`
- `/channel/user-release.json`
- `/support/index.json`
- `/support/recovery.json`
- `/payloads/index.json`
- `/payloads/aios/<release-id>/manifest.json`
- `/payloads/aios/<release-id>/checksums.json`
- `/payloads/aios/<release-id>/signatures.json`
- `/install/bootstrap.json`

The hosted service may not:

- Sign payloads or metadata.
- Store or read private signing material.
- Install, activate, or rollback a system.
- Mutate active slots, boot metadata, production rings, registries, or fleet state.
- Accept support uploads.
- Dispatch remote commands.
- Grant TUI, model replay, or shell authority.

## TLS And DNS Threats

### Threats

- DNS misbinding routes a client to a different host.
- Local DNS cache returns stale or attacker-controlled records.
- HTTP downgrade exposes metadata to observation or tampering before local verification.
- TLS certificate misissuance or expiry blocks safe bootstrap.
- CDN or proxy cache serves stale metadata.

### RC6 Controls

- Validators must use explicit host/IP binding when local DNS is untrusted.
- The mirror descriptor must keep `production_ready_claim=false` until TLS is provisioned, verified, and continuously monitored.
- HTTP may remain available for non-GA inspection, but clients must treat HTTP metadata as candidate data only.
- Installer/bootstrap clients must verify schema, hashes, freshness, signatures, revocation, compatibility, and rollback metadata locally.
- Cache headers for trust metadata must prefer `no-store` or `no-cache`.
- TLS enablement must be evidenced before any GA claim or install authorization claim.

## Static Hosting And Storage Threats

### Threats

- Static root escape exposes unintended files.
- Directory listing reveals unpublished artifacts.
- Large payload upload or accidental image hosting exhausts the limited mirror host.
- Metadata drift causes frontend, channel index, bootstrap, and payload index to disagree.
- MIME confusion makes JSON or assets executable in unintended contexts.

### RC6 Controls

- Nginx root remains `/srv/aios-mirror`.
- `autoindex off` is mandatory.
- Only `GET` and `HEAD` are allowed for public static endpoints.
- `client_max_body_size` remains small because the mirror does not accept uploads.
- JSON endpoints are small metadata files, not image payloads.
- Large payload URLs are forbidden unless a storage policy explicitly allows them.
- Suggested RC6 metadata size ceilings:
  - `health.json`: 32 KiB.
  - `mirror.json`: 64 KiB.
  - `channel/index.json`: 128 KiB.
  - `payloads/index.json`: 256 KiB.
  - per-release manifest/checksum/signature metadata: 512 KiB each.
  - `install/bootstrap.json`: 128 KiB.
- Content security policy must restrict execution to local static assets.

## Signed Payload Threats

### Threats

- A placeholder signature field is misread as a valid signature.
- A stale or revoked key remains accepted by clients.
- Signature metadata is present but not bound to the payload manifest hash.
- Checksums bind metadata but not actual payload content.
- Frontend labels make an unsigned payload look installable.
- Remote service behavior is mistaken for trust authority.

### RC6 Controls

- Unsigned or placeholder payload metadata must be labeled `verification-blocked`.
- `install_allowed` and `activation_allowed` must remain false unless signature, revocation, freshness, rollback, compatibility, and exact approval gates pass.
- Signature metadata must bind release id, manifest hash, checksum set hash, revocation snapshot hash, policy version, and expiry.
- Missing signature reference is a blocking condition, not a warning.
- Revocation status must be current and non-blocking.
- Frontend copy and machine-readable metadata must distinguish `metadata-visible`, `verification-blocked`, `install-preflight-ready`, and `install-authorized`.
- The mirror must not publish any field that claims signing, activation, rollback execution, production ring mutation, remote dispatch, support upload, shell, model, or TUI authority.

## Frontend UX Threats

The AIOS mirror frontend is useful because users can inspect the distribution channel like other public mirror sites. It is risky if it turns metadata visibility into implied trust.

The frontend must:

- Show non-GA status.
- Show TLS as a GA gate until verified.
- Show payload signature status separately from endpoint reachability.
- Show storage mode and large payload policy.
- Link directly to JSON endpoints for inspection.
- Avoid external assets or third-party scripts.
- Avoid forms, uploads, login flows, signing buttons, activation buttons, rollback buttons, or remote execution affordances.

## Fail-Closed Conditions

Clients and validators must fail closed for:

- Missing or malformed TLS/storage/payload policy.
- `production_ready_claim=true`.
- Payload metadata larger than policy.
- Any large payload URL before storage policy upgrade.
- Missing manifest/checksum/signature metadata.
- Manifest hash mismatch.
- Checksum set mismatch.
- Missing or stale revocation snapshot.
- Revoked signing key.
- Stale payload metadata.
- Missing rollback baseline.
- Missing installer compatibility contract.
- Frontend or metadata authority broadening.
- POST/PUT/PATCH/DELETE accepted by the mirror.

## RC6-004 Readiness

The next mirror infrastructure task may publish a richer static portal and bounded RC6 metadata endpoints only if it preserves this model:

- Static files only.
- No large payload storage.
- No signing.
- No install, activation, rollback, upload, remote dispatch, fleet, or TUI authority.
- `production_ready_claim=false`.
- Remote validation uses explicit `curl --resolve` because local DNS is not trusted in the current environment.
