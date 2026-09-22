# ChatGPT setup

> Product availability changes over time. Check OpenAI's current Developer Mode / MCP app documentation before deployment.

## Prerequisites

Deploy the relay at a public HTTPS origin, for example:

```text
https://remote.example.com
```

The MCP endpoint is:

```text
https://remote.example.com/mcp
```

The relay publishes OAuth discovery metadata, supports Dynamic Client Registration, PKCE S256, refresh tokens, and advertises the `offline_access` scope.

## ChatGPT

In a ChatGPT workspace where custom MCP apps are available:

1. Enable Developer Mode.
2. Create a custom MCP app.
3. Enter the public `/mcp` endpoint.
4. Choose OAuth authentication if the UI asks.
5. Scan tools.
6. Complete the owner authorization page.
7. Test with a paired device.

OpenAI currently documents full write/modify MCP support for Business and Enterprise/Edu workspaces; Pro custom MCP access is more limited. Treat this as product-dependent rather than a guarantee from this repository.

## Local-only servers

ChatGPT does not directly connect to a local stdio MCP server. Open Remote MCP provides a remote HTTPS MCP surface backed by outbound device connections.
