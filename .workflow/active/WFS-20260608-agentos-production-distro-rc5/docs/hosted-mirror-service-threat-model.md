# Hosted Mirror Service Threat Model

## Scope

This threat model covers the RC5 hosted mirror service framework for `aios.w33d.xyz` on `47.101.11.109`. The service is static, metadata-only, and non-GA. It exists to prove controlled hosted transport mechanics before AIOS claims a generally available distribution channel.

## Protected Assets

- RC4 final audit hash binding.
- RC4 hosted transport manifest hash binding.
- RC4 mirror publication hash binding.
- RC5 channel metadata and health metadata.
- Future public signature and revocation metadata.
- Server storage budget and service availability.
- Operator trust in the service boundary.

Private signing material is not a protected asset of the mirror because it must not be present on the mirror host.

## Threats

### DNS Or Routing Misbinding

`aios.w33d.xyz` may resolve to the wrong host, stale host, or a host serving unrelated content.

Required controls:

- Health metadata must name `aios.w33d.xyz`.
- Verifier must check expected schema and service id.
- RC5 cannot treat DNS reachability as trust.

### TLS Absence Or Downgrade

HTTP can prove basic reachability but cannot support a GA trust claim.

Required controls:

- RC5 may start with HTTP framework evidence only.
- TLS is required before any GA claim.
- Verifier must record whether TLS is present and fail GA gates if absent.

### Static Root Escape

Nginx misconfiguration, symlinks, aliases, or directory listing may expose files outside the mirror root.

Required controls:

- Static root must be `/srv/aios-mirror`.
- Directory listing must be disabled.
- No CGI, PHP, script execution, upload, or writable web endpoint is allowed.
- Files must be explicit small JSON or text metadata.

### Metadata Tamper Or Drift

Hosted metadata may be stale, malformed, hash-drifted, or edited outside publication evidence.

Required controls:

- Channel metadata must bind RC4 final audit, hosted transport manifest, and mirror publication hashes.
- Freshness window must be explicit.
- Local verifier and fail-closed fixtures must reject missing, stale, or mismatched metadata.

### Secret Or Authority Leak

Metadata, logs, config, or scripts may leak private key paths, signer tokens, Authorization headers, or host-local absolute paths.

Required controls:

- Secret markers are blocked in local evidence and hosted metadata.
- Mirror must not contain private signing material.
- Nginx logs are standard request logs only.
- Support bundles must remain redacted.

### Authority Broadening

The mirror may accidentally advertise signing, activation, rollback, remote dispatch, production ring mutation, or TUI authority.

Required controls:

- Health and channel metadata must state `signing_authority=false` and `activation_authority=false`.
- User install/update boundary treats the mirror as transport only.
- Any advertised activation or signing authority is a blocking failure.

### Storage Exhaustion Or Payload Creep

Large release artifacts may consume the limited server storage or bypass future object storage planning.

Required controls:

- RC5 service framework is metadata-only.
- Large payload references are blocked until storage policy is upgraded.
- Placeholder release directories must clearly mark payload storage as deferred.

### Cache Poisoning Or Stale CDN Semantics

Static metadata can be cached longer than its freshness window.

Required controls:

- Health metadata should use conservative cache headers.
- Channel metadata freshness must be verified by clients.
- Future mirror verifier must compare hosted freshness against local evidence.

## Non-GA Boundary

RC5 is not GA until all of these are proven:

- TLS endpoint evidence.
- Hosted metadata verifier evidence.
- Fail-closed fixtures for hosted metadata.
- Signed channel consumption from the hosted endpoint.
- Rollback execution drill evidence.
- Controlled multi-node canary execution evidence.
- Support and recovery operations for hosted failures.
- Storage upgrade or explicit payload hosting policy.

## Completion Criteria

RC5-003 is complete when this threat model exists, evidence records all blocking threat classes, and the next executable task is `RC5-010`.
