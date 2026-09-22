# Architecture

```text
MCP client
   |
   | Streamable HTTP + OAuth bearer token
   v
Open Remote MCP relay
   |-- OAuth authorization server
   |-- dynamic client registration
   |-- SQLite state + audit
   |-- web control plane
   |
   | outbound WebSocket
   v
Device agent
   |-- local capability declaration
   |-- local root enforcement
   |-- optional shell
   v
Host filesystem / processes
```

## Trust model

The relay is a policy and routing layer. The device agent is the final local enforcement layer.

A dashboard policy can narrow a device from, for example, `read_file + write_file` to only `read_file`. It cannot remotely turn on shell when the device was started with `ALLOW_SHELL=false`, nor can it add filesystem roots.

## OAuth

The relay exposes:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-protected-resource/mcp`
- `/.well-known/oauth-authorization-server`
- `/oauth/register`
- `/oauth/authorize`
- `/oauth/token`

MCP clients use Dynamic Client Registration, Authorization Code + PKCE S256, and refresh tokens. The relay also supports the OAuth Device Authorization grant for local agent pairing.

## Persistence

SQLite stores OAuth clients, one-time codes, token hashes, device registrations, device policies, and audit events. Live WebSocket objects remain in memory and are reconstructed when agents reconnect.
