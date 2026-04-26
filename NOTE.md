# About this repository

Public source mirror of the `@snitchplugin/cli` npm package.

- **npm:** https://www.npmjs.com/package/@snitchplugin/cli
- **Product:** https://snitchplugin.com
- **Support:** eric.waters@snitchplugin.com

## What's here

- `src/` — TypeScript source for the CLI: arg parsing, scan flow, multi-
  agent orchestrator, subprocess handling for local AI CLIs (Claude Code,
  Codex, Gemini), config store, first-run wizard, and the shared helpers
  in `src/_shared/` (methodology fetcher, license API client, SARIF
  formatter, hosted-provider adapters).
- `tests/` — Vitest suite. 80+ tests covering args, config, git utilities,
  the prompt-injection gate, providers, and remote-clone handling.
- `scripts/` — Build helpers: `postbuild.cjs` renames the ncc output and
  prepends the shebang; `prepack.cjs` strips any residual source-map
  references before publish.
- `package.json`, `tsconfig.json`, `vitest.config.ts` — Build + test
  config.

## Build

```sh
npm install
npm run build
node dist/cli.js help
```

## License

Business Source License 1.1. Production use of the software requires a
current Snitch subscription. Reading, evaluation, and personal use are
permitted without one. The license converts to Apache License 2.0 four
years after each release. See `LICENSE`.

## Reporting a security issue

Email `security@snitchplugin.com` (do not file a public GitHub issue).
We respond within two business days.
