# Renovate Integration

This repository uses [Renovate](https://docs.renovatebot.com/) to keep Go
modules, Docker base images, GitHub Actions, and pre-commit hook versions up to
date. Renovate runs as a self-hosted GitHub Action — no external Renovate app
is installed.

- Config: [`.github/renovate.json5`](../.github/renovate.json5)
- Workflow: [`.github/workflows/renovate.yaml`](../.github/workflows/renovate.yaml)

## Execution

Renovate runs via the `renovate.yaml` workflow:

| Trigger | Purpose |
|---------|---------|
| `schedule` (`0 6 * * *`) | Daily run at 06:00 UTC |
| `workflow_dispatch` | Manual trigger with `dryRun`, `logLevel`, and `repoCache` inputs |

The workflow authenticates against GitHub using the `RENOVATE_TOKEN` repository
secret and is scoped to `madic-creates/claude-alert-analyzer` via
`repositories` in the config.

### Repository cache

To avoid rescanning the repo from scratch on every run, the workflow
persists `/tmp/renovate/cache/renovate/repository` as a workflow artifact
(`renovate-cache`, 1 day retention) and restores it before the next run. The
`repoCache` dispatch input can toggle or reset this cache:

- `enabled` (default) — use and update the cache
- `disabled` — skip cache download and upload
- `reset` — ignore the existing cache; the next run rebuilds it

## Managed updates

Renovate extends [`config:recommended`](https://docs.renovatebot.com/presets-config/#configrecommended)
and additionally enables:

| Manager | Source |
|---------|--------|
| `gomod` | `go.mod` / `go.sum` |
| `dockerfile` | `Dockerfile` FROM directives |
| `github-actions` | `.github/workflows/*.yaml` action versions |
| `pre-commit` | `.pre-commit-config.yaml` hook revs (explicitly enabled via `pre-commit.enabled: true`) |

## Automerge policy

| Update type | Behaviour |
|-------------|-----------|
| `patch` | Automerged |
| `minor` | Automerged |
| `major` | Manual review required |

`automergeType: 'branch'` means Renovate pushes directly to a branch and
merges without opening a PR for qualifying updates. `ignoreTests: true`
bypasses the branch-protection status checks for the automerge path — CI still
runs on the resulting main-branch commit.

`prConcurrentLimit: 0` and `prHourlyLimit: 0` remove rate limits, so Renovate
can open as many PRs as needed in a single run.

## Package rules

### `k8s.io/*` grouping

```json5
{
  matchManagers: ['gomod'],
  matchPackageNames: [
    'k8s.io/api',
    'k8s.io/apimachinery',
    'k8s.io/client-go',
  ],
  groupName: 'k8s.io',
}
```

The Kubernetes client libraries must stay on the same minor version — mixing
them breaks the build. Renovate bundles them into a single PR/branch so they
are always updated atomically.

## Release-age gating

```json5
minimumReleaseAge: '5 days',
minimumReleaseAgeBehaviour: 'timestamp-optional',
internalChecksFilter: 'strict',
```

- `minimumReleaseAge: '5 days'` — new releases must exist for at least five
  days before Renovate proposes them. Filters out releases that get yanked
  shortly after publishing.
- `minimumReleaseAgeBehaviour: 'timestamp-optional'` — apply the age check
  only when the datasource provides a release timestamp. Without this, Docker
  images without per-tag timestamps (common on GHCR) would stay pending
  forever and get filtered out by `internalChecksFilter: 'strict'`, so no
  update PR would ever be opened.
- `internalChecksFilter: 'strict'` — hide updates that do not satisfy every
  internal check (including the age check above).

## Assignees

All PRs opened by Renovate are auto-assigned to `madic-creates`. The
`gitAuthor` on Renovate commits is `Renovate Bot <bot@renovateapp.com>`.

## Manual runs

Trigger a one-off run from the **Actions** tab → **Run renovatebot for
updates** → **Run workflow**. Useful inputs:

- `dryRun: true` — log what would change without opening PRs
- `logLevel: debug` — verbose output for troubleshooting
- `repoCache: reset` — rebuild the cache if it looks stale or corrupt

## Troubleshooting

- **Expected update not proposed:** check the last Renovate run logs for the
  dependency. Most common cause is the `minimumReleaseAge` (5 days) not yet
  elapsed, or the datasource filtered by `internalChecksFilter: 'strict'`.
- **Docker image never updates:** verify the image source provides release
  timestamps. `timestamp-optional` should cover GHCR-hosted images; if the
  image still hangs, run with `logLevel: debug` and inspect
  `pendingChecks`/`internalChecksFilter` output.
- **k8s.io update proposed for only one package:** the grouping rule in
  `packageRules` ensures all three libraries move together — if only one
  appears, the config change was dropped or the package name does not match.
- **Cache-related oddities:** re-run the workflow with `repoCache: reset` to
  force a cache rebuild.
