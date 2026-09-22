# Security model

Open Remote MCP deliberately separates **cloud policy** from **local authority**.

## Boundaries

1. The relay authenticates MCP clients with OAuth access tokens.
2. Each device is paired separately and receives its own device credential.
3. The dashboard can disable tools per device, but cannot grant a capability the local agent did not expose.
4. File tools enforce `ALLOWED_ROOTS` on the device using real paths, including symlink resolution.
5. Shell execution is disabled by default.

## Important shell warning

`ALLOW_SHELL=true` grants command execution with the authority of the OS account running the agent. `ALLOWED_ROOTS` restricts the built-in file tools, **not arbitrary shell commands**. If you need stronger isolation, run the agent under a dedicated OS account, container, or VM.

## Secrets

- Use a strong `ADMIN_PASSWORD`.
- Use a long random `SESSION_SECRET`.
- Device credentials are stored locally at `~/.open-remote-mcp/credentials.json` with mode `0600` unless overridden.
- OAuth access tokens, refresh tokens, and device tokens are stored only as SHA-256 hashes in SQLite.

## Network

Use HTTPS/WSS for any non-local deployment. Do not expose a development instance with default secrets to the public internet.

## Reporting

For vulnerabilities, prefer a GitHub Security Advisory instead of a public issue.
