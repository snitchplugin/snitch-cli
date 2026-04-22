# Snitch CLI

Local AI security scanner. Runs on your laptop with your own Claude Code, Codex, Gemini, or OpenRouter key. Source code never leaves your machine.

You get a markdown report and a SARIF 2.1.0 file, ready for GitHub Code Scanning or any SARIF-aware CI.

## Install

```sh
npm i -g @snitchplugin/cli
```

Requires Node 20 or newer. If you don't have Node, use the static binary from Homebrew instead:

```sh
brew install snitchplugin/tap/snitch
```

Both paths put `snitch` on your PATH.

## Authenticate

Get a license key from https://snitchplugin.com/pricing (free tier is 50 scans a month, no card).

```sh
snitch auth --key snch_your_key_here
```

This validates the key against `snitchplugin.com`, saves it to `~/.snitch/config.json` (0600), and never asks again.

## Scan

```sh
cd your-repo
snitch scan                  # changed files vs origin/main
snitch scan --full           # every tracked file in the repo
snitch scan @src/auth.ts     # one file
snitch scan @packages/api    # an entire folder
snitch scan #123             # files in a specific GitHub PR (requires gh CLI)
```

Output lands in the repo root as `SECURITY_AUDIT_REPORT.md` and `SECURITY_AUDIT_REPORT.sarif`.

## What it looks for

68 categories across:

- Injection and data handling (SQL injection, XSS, SSRF, path traversal, unsafe deserialization)
- Authentication and session (JWT, OAuth, CSRF, cookie flags)
- Secrets and credentials (hardcoded keys, .env in git, weak key generation)
- AI-specific risks (prompt injection, unsanitized LLM output, tool-call abuse)
- Supply chain (dependency confusion, unsafe post-install, typosquatting)
- Access control (IDOR, missing authz, RLS bypass)
- Cryptography (weak hashing, predictable IVs, custom crypto)
- Platform-specific (Cloudflare Workers, Next.js, Supabase, React Native)

The free tier runs the 10 core categories. Pro and Team unlock all 68.

## Providers

Pick any of these. All run locally; the AI call is a subprocess or a direct API call with your own key.

```sh
# Claude Code (default if installed)
snitch scan --provider local-cli --model claude

# OpenAI Codex
snitch scan --provider local-cli --model codex

# Gemini CLI
snitch scan --provider local-cli --model gemini

# Direct OpenRouter (pay by the token)
export OPENROUTER_API_KEY=sk-or-...
snitch scan --provider openrouter
```

## CI

Set `SNITCH_LICENSE_KEY` as a secret, add a step that installs the CLI, then run `snitch scan`. The SARIF output uploads cleanly to GitHub Code Scanning.

```yaml
- run: npm i -g @snitchplugin/cli
- run: snitch scan
  env:
    SNITCH_LICENSE_KEY: ${{ secrets.SNITCH_LICENSE_KEY }}
    OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: SECURITY_AUDIT_REPORT.sarif
```

## Privacy

The CLI only calls snitchplugin.com for:

- License key validation (`/api/github/billing`)
- Methodology download per scan (`/api/skill/methodology`)
- Scan metadata: repo name, file count, finding counts (`/api/scan/event`)

Your source code is never uploaded. The AI call either runs on your laptop as a subprocess, or goes directly to your chosen provider (OpenRouter, etc.) with your own key.

## Links

- Pricing and plans: https://snitchplugin.com/pricing
- Product page: https://snitchplugin.com/cli
- Dashboard: https://snitchplugin.com/dashboard/github
- Support: eric.waters@snitchplugin.com

## License

Proprietary. A valid license key is required at runtime. See https://snitchplugin.com/pricing.
