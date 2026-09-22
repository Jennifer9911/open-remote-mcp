# Open Remote MCP

An open-source remote MCP control plane that lets AI clients securely reach tools running on your own computers.

> **Status:** early MVP. Relay, device agent, Remote MCP endpoint, and web control plane are implemented. OAuth 2.1 / PKCE, durable persistence, and production hardening are next.

## Architecture

```text
AI client / ChatGPT / Claude / Cursor
                |
       Streamable HTTP MCP
                |
        Open Remote MCP relay
          /             \\
   web control plane    WebSocket
                          |
                    local device agent
                          |
                scoped files / optional shell
```

Local MCP servers are powerful, but web AI clients cannot directly reach `stdio` processes on a laptop. Open Remote MCP adds a thin relay and an outbound agent so a compatible AI client can call explicitly exposed tools on one or more machines.

## MVP features

- Remote MCP endpoint at `/mcp`
- Outbound WebSocket device agent
- Multi-device routing with explicit `deviceId`
- Device ping, directory listing, UTF-8 file read/write
- Optional shell command execution
- Agent-side filesystem root enforcement
- Separate MCP-client and device-agent credentials
- Web dashboard for devices, activity, security posture, and setup
- In-memory tool-call audit trail

## Security defaults

- `ALLOW_SHELL=false` by default.
- Every filesystem path is resolved and checked against `ALLOWED_ROOTS` on the **device agent**.
- Relay access and device-agent access use separate tokens.
- An offline agent is unreachable.
- The MVP is not a sandbox. For hostile or untrusted workloads, use a dedicated OS account, VM, or container.

## Quick start

Requirements: Node.js 20+.

```bash
npm install
```

Terminal 1 — relay + dashboard:

```bash
ADMIN_TOKEN=local-admin AGENT_SHARED_TOKEN=local-device npm run dev
```

Terminal 2 — device agent:

```bash
REMOTE_MCP_SERVER=ws://localhost:8787/agent \\
DEVICE_TOKEN=local-device \\
DEVICE_ID=my-laptop \\
DEVICE_NAME="My laptop" \\
ALLOWED_ROOTS="$HOME/projects" \\
npm run dev -w @open-remote-mcp/agent
```

Open `http://localhost:5173`.

## MCP client

The MVP uses bearer-token auth. OAuth is the next major milestone.

- MCP URL: `https://YOUR_HOST/mcp`
- Authorization: `Bearer <ADMIN_TOKEN>`

Tools: `list_devices`, `ping_device`, `list_directory`, `read_file`, `write_file`, `run_command`.

## Repository layout

```text
apps/
  server/   MCP endpoint, relay, REST API, activity log
  agent/    cross-platform outbound device agent
  web/      React/Vite control plane
```

## Roadmap

### 0.2
- OAuth 2.1 authorization server with PKCE
- RFC 8628 device authorization and pairing codes
- SQLite/Postgres persistence
- Device revoke / rename / last-seen metadata
- Per-device policy editor

### 0.3
- Long-running process sessions and streamed output
- Fine-grained tool permissions and workspace aliases
- Signed agent releases for macOS, Windows, and Linux
- Docker deployment and reverse-proxy examples

### 1.0
- OpenID Connect integration
- Team / organization model
- Approval policies for destructive calls
- Structured audit export
- Public MCP client compatibility matrix

## Upstream inspiration

This is an independent open-source implementation inspired by the architecture of Remote Desktop Commander and the local capabilities of DesktopCommanderMCP.

- `wonderwhy-er/DesktopCommanderMCP` is MIT licensed.
- The hosted service behind `desktop-commander/remote-desktop-commander` is not open source; this repository does not copy that hosted implementation.

See `NOTICE.md`.

## License

MIT
