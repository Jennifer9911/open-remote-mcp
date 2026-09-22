# Contributing

Contributions are welcome.

## Principles

- Keep the project AI-client agnostic.
- Keep the device agent platform agnostic where practical.
- Default to least privilege.
- Server policy may narrow local authority, never broaden it.
- New destructive capabilities should be explicit and auditable.

## Development

```bash
npm install
npm run typecheck
npm run test
npm run build
npm run dev
```

Node.js 22.5+ is required because the relay uses the built-in SQLite module.
