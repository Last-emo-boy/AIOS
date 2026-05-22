# Alpha Runtime Config Defaults

Source task: `TASK-DALPHA-004`
Workflow: `WFS-20260523-agentos-distribution-alpha`
Input manifest: `.workflow/active/WFS-20260523-agentos-distribution-alpha/docs/rootfs-runtime-install-manifest.md`

## Purpose

Distribution Alpha needs source-controlled defaults for the runtime config
artifacts that later rootfs staging and image assembly will install under
`/etc/agentos/`. These defaults mirror the completed runtime contracts; they do
not create a new authority layer.

The package defaults live under:

```text
packaging/agentos/rootfs/etc/agentos/
  policy/policy-pack.json
  tools/semantic-tools.json
  model-broker.toml
```

## Config Artifacts

| Manifest ID | Source-controlled path | Rootfs target | Validation |
|---|---|---|---|
| `policy.pack` | `packaging/agentos/rootfs/etc/agentos/policy/policy-pack.json` | `/etc/agentos/policy/policy-pack.json` | JSON parses; `policy_version=policy-v1`; exact approval binding; normal-mode `shell.exec` denied; denied effects do not prepare |
| `tools.semantic` | `packaging/agentos/rootfs/etc/agentos/tools/semantic-tools.json` | `/etc/agentos/tools/semantic-tools.json` | JSON parses; allowed tools match current semantic router; `shell.exec` absent |
| `model_broker.config` | `packaging/agentos/rootfs/etc/agentos/model-broker.toml` | `/etc/agentos/model-broker.toml` | TOML parses; default mode is `stub`; stub provider needs no network or credentials; remote provider disabled and optional |

## Policy Defaults

`policy-pack.json` preserves the capability policy from `docs/capability-policy.md`:

- `read-only` is allowed without approval.
- `write-with-diff`, `execute-with-confirmation`, and
  `privileged-with-human-approval` pause without exact approval.
- `never` is denied with or without approval.
- Approval tokens bind actor, tool, resource, parameter hash, expiry, and policy
  version.
- Broad session approval is forbidden.
- Normal-mode `shell.exec` is denied.
- Denied policy decisions write `PolicyEvaluated` and do not prepare effects.

## Semantic Tool Defaults

`semantic-tools.json` contains only typed semantic tools already represented by
the current router:

- `svc.logs`
- `svc.status`
- `http.check`
- `config.test`
- `fs.read`
- `fs.write.diff`
- `svc.restart`
- `audit.show`
- `rollback.trigger`

`shell.exec` is intentionally absent from the tool list. The policy pack also
contains an explicit normal-mode denial for `shell.exec` so the absence is not
the only line of defense.

## ModelBroker Defaults

`model-broker.toml` defaults to stub/local-only mode:

- `mode = "stub"`
- `network_required = false`
- `default_provider = "stub-local"`
- `providers.stub-local.requires_credentials = false`
- `providers.remote.enabled = false`
- `providers.remote.required_for_acceptance = false`

Provider logs must be metadata-only. Raw prompts, raw observations, raw secrets,
tokens, passwords, and provider credentials are not valid package defaults.

## Validation Commands

```powershell
Get-Content packaging/agentos/rootfs/etc/agentos/policy/policy-pack.json -Raw | ConvertFrom-Json
Get-Content packaging/agentos/rootfs/etc/agentos/tools/semantic-tools.json -Raw | ConvertFrom-Json
python -c "import pathlib,tomllib; tomllib.loads(pathlib.Path('packaging/agentos/rootfs/etc/agentos/model-broker.toml').read_text())"
rg '"shell.exec"' packaging/agentos/rootfs/etc/agentos/tools/semantic-tools.json
rg 'normal_shell.*deny|stub-local|required_for_acceptance = false' packaging/agentos/rootfs/etc/agentos
```

The `rg '"shell.exec"'` check is expected to return no matches for the semantic
tool manifest. `shell.exec` may appear in `policy-pack.json` only as an explicit
deny entry.

## Handoff

- `TASK-DALPHA-003` consumes these defaults in rootfs staging validation.
- `TASK-DALPHA-005` installs them into runtime-aware image assembly.
- `TASK-DALPHA-006` uses them for packaged service recovery smoke.
- `TASK-DALPHA-008` records their hashes in Alpha provenance.

## Completion Criteria

`TASK-DALPHA-004` is complete when the packageable defaults exist, parse, keep
normal-mode shell denied, default ModelBroker to offline stub/local mode, and do
not contain raw secrets or credentials.
