# Pre-Commit Integration

This repository uses [pre-commit](https://pre-commit.com/) to automatically
check and format code before every commit. The configuration lives in
[`.pre-commit-config.yaml`](../.pre-commit-config.yaml).

## Setup

```bash
# Install pre-commit (one-time, system-wide)
pip install pre-commit
# or via a package manager, e.g.
pacman -S pre-commit

# Install the hooks into the local .git/hooks/ directory
pre-commit install
```

From now on the hooks run automatically on every `git commit`.

## Manual execution

```bash
# Run all hooks against all files
pre-commit run --all-files

# Run a specific hook
pre-commit run golangci-lint --all-files

# Bump hook versions to the latest releases
pre-commit autoupdate
```

## Configured hooks

### General hygiene — [`pre-commit/pre-commit-hooks`](https://github.com/pre-commit/pre-commit-hooks)

| Hook | Purpose |
|------|---------|
| `trailing-whitespace` | Trims whitespace at the end of lines |
| `end-of-file-fixer` | Ensures files end with exactly one newline |
| `mixed-line-ending` | Normalises line endings |
| `detect-private-key` | Prevents accidental commits of private keys (`internal/shared/redact_test.go` is excluded because it contains test fixtures) |
| `check-merge-conflict` | Blocks commits with unresolved merge markers |

### Character normalisation — [`Lucas-C/pre-commit-hooks`](https://github.com/Lucas-C/pre-commit-hooks)

| Hook | Purpose |
|------|---------|
| `remove-crlf` | Replaces CRLF with LF |

> `remove-tabs` is currently disabled in the config.

### Smart-quote fix — [`sirosen/fix-smartquotes`](https://github.com/sirosen/fix-smartquotes)

| Hook | Purpose |
|------|---------|
| `fix-smartquotes` | Replaces typographic quotes with ASCII `"` / `'` |

### Go linting — [`golangci/golangci-lint`](https://github.com/golangci/golangci-lint)

| Hook | Purpose |
|------|---------|
| `golangci-lint` | Lints only the currently changed Go files (`--new-from-rev HEAD --fix`) — fast enough for pre-commit |
| `golangci-lint-config-verify` | Validates the syntax of [`.golangci.yml`](../.golangci.yml) |

The linter selection (`errcheck`, `govet`, `staticcheck`, `unused`,
`ineffassign`) and exclusions are defined in `.golangci.yml`. The CI workflow
additionally runs the full variant across all files via
`golangci/golangci-lint-action`.

## Automatic updates

Hook versions are maintained by [Renovate](../.github/renovate.json5) — the
`pre-commit` manager is explicitly enabled. Minor and patch updates are merged
automatically, major updates require manual approval.

Alternatively, run `pre-commit autoupdate` locally to bump
`.pre-commit-config.yaml` to the latest tags.

## Troubleshooting

- **A hook fails even though the code looks correct:** run `pre-commit clean` to
  clear the hook cache, then `pre-commit run --all-files` again.
- **golangci-lint reports different findings locally vs. in CI:** the
  pre-commit hook uses `--new-from-rev HEAD`, i.e. only newly introduced
  findings block the commit. CI lints the entire codebase.
- **Bypass a hook (only in exceptional cases):** `git commit --no-verify`. CI
  will still catch skipped findings.
