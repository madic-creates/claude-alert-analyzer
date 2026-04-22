# GHCR Image Cleanup

This repository publishes two container images to `ghcr.io` on every push to
`main`:

- `ghcr.io/<owner>/claude-alert-kubernetes-analyzer`
- `ghcr.io/<owner>/claude-alert-checkmk-analyzer`

Every build produces a fresh short-SHA tag plus an updated `latest` alias (see
[`build.yaml`](../.github/workflows/build.yaml)). Without pruning, the tag list
grows forever. The `cleanup-ghcr.yaml` workflow trims it back.

- Workflow: [`.github/workflows/cleanup-ghcr.yaml`](../.github/workflows/cleanup-ghcr.yaml)

## Execution

| Trigger | Purpose |
|---------|---------|
| `schedule` (`0 4 * * 0`) | Weekly run, Sundays 04:00 UTC |
| `workflow_dispatch` | Manual trigger with `dry_run` input |

The job runs on a matrix of both package names and uses the built-in
`GITHUB_TOKEN` with `packages: write`. A `concurrency` group
(`cleanup-ghcr`, `cancel-in-progress: false`) prevents overlapping runs from
racing against each other on the GHCR API.

## Retention policy

For each package:

| Category | Action |
|----------|--------|
| Tagged versions — newest `KEEP_TAGGED` (default **10**) | Kept |
| Tagged versions — older than the top `KEEP_TAGGED` | Deleted |
| Untagged versions (dangling manifests) | Deleted, always |

Because versions are sorted by `created_at` (newest first) and `latest` always
points to the most recent push, `latest` is guaranteed to be part of the kept
top-N — it is never deleted by accident.

`KEEP_TAGGED` is set inline in the workflow `env:` block. Bump it to retain
more history, lower it to prune more aggressively.

## Dry run

Manually dispatch the workflow with `dry_run: true` to see what *would* be
removed without touching anything:

```
Actions → Cleanup old container images → Run workflow → dry_run: true
```

The job logs every candidate as `id=… created=… tags=…` and exits before any
delete call.

## Rate limiting

Deletions are paced with `sleep 0.2` between API calls to stay under GHCR's
secondary rate limits when a backlog accumulates. Individual delete failures
are counted and the job exits non-zero at the end if any delete failed — the
rest of the batch still runs.

## Note: high-frequency builds

The build workflow produces a new image version for every push to `main` that
touches `cmd/**`, `internal/**`, the `Dockerfile`, or `go.mod`/`go.sum`. If
the release cadence increases — for example, an hourly automated release or a
busy merge day — many new SHA-tagged images accumulate on GHCR very quickly:

- **~24 pushes/day** → ~168 new tagged versions per week, per package.
- With `KEEP_TAGGED=10` and weekly cleanup, the package can hold **hundreds
  of stale tags** between runs.

This has two practical consequences:

1. **Storage.** Each untagged or superseded version still occupies GHCR
   storage until cleanup runs.
2. **Pagination / API cost.** The cleanup job pages through the full version
   list via `gh api --paginate`; very long lists make the Sunday run slower
   and closer to secondary rate limits.

If high-frequency builds are expected, consider one of:

- Raising the `schedule` frequency (e.g. daily instead of weekly).
- Lowering `KEEP_TAGGED` if fewer historical SHAs are actually useful.
- Restricting which pushes produce an image (e.g. only tagged releases
  rather than every commit).

## Troubleshooting

- **Job fails with `Resource not accessible by integration`:** the workflow
  needs `packages: write`. Verify the `permissions:` block is intact and that
  the repository owner matches `OWNER` (the workflow uses the
  `/users/<owner>/packages/...` endpoint, which requires the owner to be a
  user account; organization-owned packages need the `/orgs/...` endpoint
  instead).
- **`latest` got deleted:** should not happen as long as `latest` points to
  the newest push — it will always be inside the kept top-N. If it did
  happen, the package probably has more than `KEEP_TAGGED` tagged versions
  pushed *after* `latest` was last moved, which means `latest` is stale.
  Re-run the build workflow to re-publish `latest`.
- **Cleanup is slow / hits rate limits:** increase the `sleep` between
  deletes, or reduce the backlog by running cleanup more frequently.
