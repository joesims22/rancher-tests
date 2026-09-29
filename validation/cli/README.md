# Rancher CLI Validation

These tests target the new CLI from `rancher/rancher-cli`. They do not target the older `rancher/cli` v2 binary, even though both executables are named `rancher`.

The new CLI must already be installed in `PATH`. The tests do not download or pin it. At startup, the suite runs `rancher schema` and checks for commands unique to the new CLI.

## Configuration

Configure the Rancher test framework normally:

```yaml
rancher:
  host: "rancher.example.com"
  adminToken: "token-id:token-secret"
  cleanup: true
  caCerts: |-
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
```

`caCerts` is required for a self-signed or privately issued Rancher certificate. Publicly trusted endpoints use the system trust store. The suite does not disable TLS verification.

Do not set `rancherCLI: true`. That option initializes Shepherd's client for the older CLI and uses its legacy login syntax. This suite explicitly disables that initialization.

Each admin or standard-user CLI identity receives a temporary `RANCHER_CLI_CONFIG_DIR` and `RANCHER_CLI_CREDENTIAL_STORE=file`. Tests never import `cli2.json`, use an existing CLI login, write the default Rancher CLI config, or access the operating-system keychain.

## P0 Coverage

The initial suite covers:

- schema compatibility and isolated config diagnostics;
- admin and standard-user token login and status;
- representative cluster, project, namespace, user, and setting reads;
- cluster and user inspection plus kubeconfig generation;
- access decisions, rules, cluster/project visibility, reverse lookup, and explanation;
- reversible project and namespace creation, patching, membership changes, and deletion;
- a standard-user project-owner workflow and an out-of-scope denial.

CLI output validates the command contract. Wrangler and Steve-backed APIs independently validate Rancher-side state. See [COMMAND_COVERAGE.md](COMMAND_COVERAGE.md) for the complete staged inventory.

## Running

Compile without executing live tests:

```bash
go test -tags=validation ./validation/cli -run '^$'
```

Run the live suite:

```bash
gotestsum --format standard-verbose \
  --packages=github.com/rancher/tests/validation/cli \
  --junitfile results.xml -- \
  -count=1 -timeout=60m -tags=validation -v -run 'TestCLITestSuite$'
```

Run one workflow by appending its test name, for example `-run 'TestCLITestSuite/TestAuthentication$'`.