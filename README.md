# Open Remote MCP

Open Remote MCP is a self-hosted, open-source control plane for securely connecting remote MCP clients to tools running on your own computers.

**v0.2.0** adds OAuth authorization, browser-based device pairing, SQLite persistence, per-device tool policy, a protected visual dashboard, and persistent audit logs.

## What it does

```text
ChatGPT / Claude / Cursor / any compatible MCP client
                    |
             HTTPS + OAuth
                    v
          Open Remote MCP relay
          |        |        |
        OAuth    SQLite   Dashboard
                    |
             outbound WSS
                    v
              device agent
                    |
        scoped files / optional shell
```

The local device initiates the connection, so the relay never needs an inbound port on your laptop or workstation.

## Highlights

- Streamable HTTP MCP endpoint at `/mcp`.
- OAuth discovery with Protected Resource Metadata and Authorization Server Metadata.
- Dynamic Client Registration.
- Authorization Code flow with PKCE S256.
- Refresh tokens and advertised `offline_access` support.
- OAuth Device Authorization flow for agent pairing.
- Device-specific credentials; revoke from the dashboard.
- SQLite persistence for registrations, token hashes, device state, policies, and audit events.
- Two-layer permission model: server policy can narrow tools; the agent remains the final local authority.
- Realpath-based file root enforcement, including symlink escape protection.
- Shell disabled by default.
- React/Vite web control plane.
- Docker deployment files and CI.

## Quick start

### Requirements

- Node.js 22.5+
- npm

```bash
git clone https://github.com/Jennifer9911/open-remote-mcp.git
cd open-remote-mcp
npm install
npm run typecheck
npm run test
npm run build
```

### Start the relay

```bash
PUBLIC_BASE_URL=http://localhost:8787 \
ADMIN_PASSWORD='choose-a-strong-password' \
SESSION_SECRET='choose-a-long-random-secret' \
npm start
```

The production server also serves the built web dashboard at `http://localhost:8787`.

### Start an agent

On the machine you want the MCP client to reach:

```bash
REMOTE_MCP_SERVER=ws://localhost:8787/agent \
ALLOWED_ROOTS="$HOME/projects" \
npm run agent
```

On first launch the agent prints a one-time code and verification URL. Open the URL, enter the owner password, approve the device, and return to the terminal. The device credential is then saved locally with restricted file permissions.

To expose shell execution intentionally:

```bash
ALLOW_SHELL=true npm run agent
```

> Warning: shell access has the authority of the OS account running the agent. `ALLOWED_ROOTS` constrains the built-in file tools, not arbitrary shell commands.

## Visual control plane

The dashboard provides:

- live online/offline/revoked device state;
- local capability and root visibility;
- per-device server tool policy;
- immediate device revocation;
- persisted execution audit trail;
- security posture and connection instructions.

## MCP tools

v0.2 currently exposes:

- `list_devices`
- `ping_device`
- `list_directory`
- `read_file`
- `write_file`
- `run_command` — only when enabled locally and permitted by server policy.

## OAuth endpoints

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-protected-resource/mcp`
- `/.well-known/oauth-authorization-server`
- `/oauth/register`
- `/oauth/authorize`
- `/oauth/token`
- `/oauth/device/code`

Access, refresh, and device credentials are stored in SQLite only as hashes.

## Docker

```bash
export ADMIN_PASSWORD='choose-a-strong-password'
export SESSION_SECRET='choose-a-long-random-secret'
export PUBLIC_BASE_URL='https://remote.example.com'
docker compose up -d --build
```

Put the service behind HTTPS before connecting a remote MCP client over the public internet.

## ChatGPT

See [`docs/CHATGPT.md`](docs/CHATGPT.md). ChatGPT connects to remote MCP endpoints rather than directly to local stdio servers. Product availability and write permissions depend on the ChatGPT plan/workspace and can change independently of this project.

## Security model

Read [`SECURITY.md`](SECURITY.md) before exposing the relay publicly. The key design rule is: **cloud policy may narrow local authority, never broaden it**.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Development

```bash
npm run dev       # relay + Vite dashboard
npm run typecheck
npm run test
npm run build
```

For a full local OAuth + pairing + real-agent smoke test, start a relay on port 8790 with the E2E credentials used by `scripts/e2e.mjs`, then run `npm run test:e2e`. The script exercises discovery, DCR, PKCE, refresh, device authorization, MCP execution, policy narrowing, audit persistence, and revocation.

## Project layout

```text
apps/
  server/   MCP relay, OAuth server, SQLite state, dashboard API
  agent/    outbound local device agent
  web/      visual control plane
docs/
  ARCHITECTURE.md
  CHATGPT.md
```

## Upstream context

This is an independent implementation. It was informed by the public architecture/docs of Remote Desktop Commander and by the MIT-licensed DesktopCommanderMCP project. It does not copy the proprietary hosted Remote Desktop Commander implementation. See [`NOTICE.md`](NOTICE.md).

## License

MIT
