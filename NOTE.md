# About this repository

This repo is the public source mirror of the `@snitchplugin/cli` npm package.

**Canonical:** https://www.npmjs.com/package/@snitchplugin/cli
**Product:** https://snitchplugin.com
**Support:** eric.waters@snitchplugin.com

## What's here

- `src/` — TypeScript source for the CLI orchestration: arg parsing, scan
  flow, the multi-agent orchestrator, subprocess handling for local AI CLIs
  (Claude Code, Codex, Gemini), config store, and the first-run wizard.
- `tests/` — Vitest test suite covering args, config, git utilities, gate,
  providers, and remote handling. 80+ tests.
- `scripts/` — Build helpers (postbuild rename + shebang, prepack source-map
  strip).
- `package.json`, `tsconfig.json`, `vitest.config.ts` — Build + test config.

## What's not here

A few imports in `src/` reach into `../../snitch-github/src/` for shared
helpers (methodology fetcher, license-API client, SARIF formatter, hosted-
provider adapters). Those helpers live in a separate internal repo because
they are also consumed by the GitHub Action variant. This mirror is
therefore a viewer's edition; building locally requires those helpers,
which we ship pre-bundled in the npm package's `dist/cli.js`.

If you want to inspect the bundled JS that customers actually run, install
the package and read it:

```sh
npm view @snitchplugin/cli dist
# or
npm install @snitchplugin/cli && cat node_modules/@snitchplugin/cli/dist/cli.js
```

## License

Business Source License 1.1. See `LICENSE`. Production use of the
software requires a current Snitch subscription. Reading, evaluation,
and personal use are permitted without a subscription. The license
converts to Apache 2.0 four years after each release.

## Reporting a security issue

Email `security@snitchplugin.com` (do not file a public GitHub issue).
We respond within two business days.
