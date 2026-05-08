# Release Binaries — Attach Compiled Go Binaries to GitHub Releases

**Date:** 2026-05-08
**Status:** Approved (awaiting implementation plan)
**Scope:** Extend the existing `release` job in `.github/workflows/build.yaml` to compile both analyzer binaries for `linux/amd64` and attach them (with per-file SHA-256 sidecars) to the GitHub Release that the same job creates.

## Goal

After every successful auto-release on `main`, the GitHub Release for `vX.Y.Z` carries four supplementary asset files:

| Asset | Purpose |
|---|---|
| `k8s-analyzer-v<version>-linux-amd64` | k8s-analyzer binary (linux/amd64) |
| `k8s-analyzer-v<version>-linux-amd64.sha256` | SHA-256 of above, in `sha256sum -c`-compatible format |
| `checkmk-analyzer-v<version>-linux-amd64` | checkmk-analyzer binary (linux/amd64) |
| `checkmk-analyzer-v<version>-linux-amd64.sha256` | SHA-256 of above, in `sha256sum -c`-compatible format |

The Docker images on GHCR remain the canonical deliverables; the binaries are supplementary for operators who want to run the analyzer outside of a container or verify a hash before deployment.

## Non-Goals

- Multi-platform builds (e.g. `linux/arm64`, `darwin/*`). Only `linux/amd64` is built — matches the existing Docker image.
- Embedding `--version` output into the binaries via `-ldflags="-X main.version=..."`. The analyzers don't currently have a `var version` symbol; a separate change can add this later.
- Reproducible-build verification beyond what `-trimpath` and pinned base toolchain already provide.
- Single combined `SHA256SUMS` file. Per-file sidecars are simpler for operators who want to download just one binary plus its hash.
- Rolling-release (or "`latest`-asset") semantics — assets are tied to specific tags and are not re-pointed.

## Workflow Architecture

The existing `release` job in `.github/workflows/build.yaml` already executes the sequence:

```
Step 0: Checkout (full history + tags)
Step 1: Install pinned semantic-release binary
Step 2: Determine next version (dry-run)
Step 3: Set up Buildx           [if version != ""]
Step 4: Log in to GHCR          [if version != ""]
Step 5: Compute image tags k8s
Step 6: Build & push k8s
Step 7: Compute image tags checkmk
Step 8: Build & push checkmk
Step 9: Publish Git tag + GitHub Release
```

This design appends four steps after Step 9, each guarded by the same `if: steps.semrel-dry.outputs.version != ''` so non-release commits skip them entirely.

```
Step 10: Set up Go              [if version != ""]
Step 11: Compile binaries       [if version != ""]
Step 12: Generate per-file SHA-256 sidecars   (combined into Step 11)
Step 13: Upload to GitHub Release             [if version != ""]
```

Step 12 collapses into Step 11 because both run in the same shell snippet.

### Step 10 — Set up Go

```yaml
- name: Set up Go
  if: steps.semrel-dry.outputs.version != ''
  uses: actions/setup-go@v6
  with:
    go-version-file: go.mod
```

Same setup as the existing `test` and `lint` jobs — `go-version-file: go.mod` keeps the toolchain in lockstep with the rest of the workflow.

### Step 11 — Compile binaries + emit SHA-256 sidecars

```yaml
- name: Compile binaries and checksums
  if: steps.semrel-dry.outputs.version != ''
  env:
    VERSION: ${{ steps.semrel-dry.outputs.version }}
  run: |
    set -euo pipefail
    for COMPONENT in k8s-analyzer checkmk-analyzer; do
      OUT="${COMPONENT}-v${VERSION}-linux-amd64"
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -trimpath -ldflags="-s -w" \
        -o "$OUT" \
        "./cmd/${COMPONENT}/"
      sha256sum "$OUT" > "${OUT}.sha256"
    done
    ls -la k8s-analyzer-* checkmk-analyzer-*
```

- `CGO_ENABLED=0` matches the project's existing build commands (see `CLAUDE.md`); the binaries are pure Go.
- `GOOS=linux GOARCH=amd64` is explicit and matches the runner's native architecture (no cross-compile needed, but the env vars document intent).
- `-trimpath` removes filesystem paths from the binary. Combined with a clean CI workspace and `-buildvcs=auto` (Go default), reruns on the same commit produce byte-stable output. This is **not** formal byte-reproducibility across machines or toolchains — for that, `-buildvcs=false` would also be needed (it would suppress embedded VCS info, losing the commit-SHA stamp). We keep the default to retain the embedded SHA, which is useful for in-binary debugging.
- `-ldflags="-s -w"` strips the symbol table and DWARF debug info (~30–40% size reduction). Go panic stack traces still show function names because they go through runtime reflection, not DWARF; debugger/core-dump workflows lose symbol names.
- `sha256sum <file>` writes `<hash>  <filename>\n`, which is directly consumable by `sha256sum -c <file>.sha256` on the operator side.
- `ls -la` at the end is informational — the workflow log shows the four files plus their sizes for sanity.

**Note on Dockerfile divergence:** the existing `Dockerfile` builds the binaries **without** `-trimpath -ldflags="-s -w"`. So the same commit produces different binary bytes between the GHCR image (Dockerfile build) and the release-asset binary (workflow build). This is intentional for now — unifying both builds is out of scope. Operators who want bit-identical content should pin to one source: either `docker pull ghcr.io/...` or release-asset download, not mix. A future change could pass these flags to the Dockerfile too.

### Step 13 — Upload to GitHub Release

```yaml
- name: Upload binaries to GitHub Release
  if: steps.semrel-dry.outputs.version != ''
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    VERSION: ${{ steps.semrel-dry.outputs.version }}
  run: |
    gh release upload "v${VERSION}" \
      "k8s-analyzer-v${VERSION}-linux-amd64" \
      "k8s-analyzer-v${VERSION}-linux-amd64.sha256" \
      "checkmk-analyzer-v${VERSION}-linux-amd64" \
      "checkmk-analyzer-v${VERSION}-linux-amd64.sha256" \
      --clobber
```

- `gh release upload` requires the release to exist — guaranteed because Step 9 (`Publish Git tag + GitHub Release`) ran successfully.
- `--clobber` makes the upload idempotent: if the same job is re-run for any reason, it overwrites existing assets rather than failing on conflict.
- `GH_TOKEN` env is set at the step level so the `gh` CLI authenticates with the workflow token. The token's `contents: write` permission (already on the release job) is what `gh release upload` needs.

## Permissions

No change. The release job already has:

```yaml
permissions:
  contents: write     # for tag + release + asset upload
  packages: write     # for image push
```

`contents: write` is what authorizes `gh release upload`. No additional scope is required.

## Atomicity & Failure Modes

The new steps come **after** the GitHub Release is published. This means the asset upload sits outside the atomic-publish window:

- **Compile fails after publish**: extremely unlikely — the same Go source compiled successfully in `test`/`lint` and the Docker `build-push` minutes earlier. If it does fail, the GitHub Release exists without binaries; manual `gh release upload` from a developer machine fixes it.
- **Upload fails after compile**: GitHub Release exists, possibly with a partial asset set. The first upload attempt populates whatever assets succeed; subsequent reruns require manual intervention because the dry-run-step on a re-triggered workflow returns empty (tag already exists), so the new steps are skipped.

In neither failure mode is correctness compromised: the canonical artifacts (Git tag, GitHub Release, GHCR images) are already in place. Binaries are best-effort supplementary.

### Why post-publish upload (not draft-first)

A more atomic alternative exists: compile binaries → create the GitHub Release as a draft → upload assets → publish (un-draft). That flow guarantees "no published release without binaries". Trade-offs:

- **Cost saved by post-publish:** the draft-first flow requires replacing or wrapping the `go-semantic-release/action` publish step, since the action publishes directly. We'd lose the action's built-in changelog generation or have to reimplement it.
- **Cost paid by post-publish:** the failure-mode window described above.

We accept the post-publish window because the published-release-without-binaries case is recoverable manually and the binaries are explicitly best-effort supplementary (Docker images on GHCR are the canonical deliverables). Build-before-publish without going draft-first would *also* be feasible (compile binaries before the publish step, gated on the same `if:` so only release commits pay the cost) — but offers no atomicity gain, only earlier failure detection. We keep the simpler post-publish ordering.

### `--clobber` semantics

The upload step uses `--clobber`. Per GH CLI docs, this **deletes the existing asset** before uploading the new one — not a transactional swap. Implications:

- In the normal flow, each release uploads each filename exactly once; `--clobber` is a no-op for first-time uploads. It only takes effect when a developer manually re-uploads.
- During a manual re-upload, if the new upload fails after the delete, the asset is gone. The release page shows a missing asset until the next manual fix.
- `--clobber` therefore is *not* a safe transactional guarantee; it's a re-upload convenience flag that accepts a delete-then-upload risk window.

### Rollback interaction

If the rollback playbook (used after the unintentional `v1.0.0` push) deletes a GitHub Release, **its attached assets are deleted with it**. There is no separate-cleanup step needed, but a rollback also implies losing the binaries, not just the release entry. Re-creating the release later with `gh release create` requires re-uploading the assets too.

## Edge Cases

- **Re-running a workflow run that already published**: Step 2 (dry-run) returns empty `outputs.version` because the tag now exists, so all four new steps are skipped. Existing assets are preserved. To force a re-upload of binaries for an existing release, run `gh release upload` manually with `--clobber`.
- **Workflow `paths:` filter**: unchanged. Docs-only and config-only commits don't trigger the workflow, so the binary steps don't run for them either — same behavior as the rest of the release job.
- **Cleanup workflow interaction**: `cleanup-ghcr.yaml` only touches GHCR container packages, not GitHub Releases. Release assets are not affected.
- **Asset size**: stripped Go binaries for these analyzers are typically 10-25 MB. GitHub Release assets are limited to 2 GB per file. No concern.
- **Filename collisions**: per-version filename suffixes (`-v0.2.0-`) prevent collisions across releases. Within a release, the four filenames are distinct.

## Operator Usage Examples

Download and verify a binary:

```bash
VERSION=v0.2.0
COMPONENT=k8s-analyzer
gh release download "$VERSION" \
  --pattern "${COMPONENT}-${VERSION}-linux-amd64" \
  --pattern "${COMPONENT}-${VERSION}-linux-amd64.sha256"
sha256sum -c "${COMPONENT}-${VERSION}-linux-amd64.sha256"
chmod +x "${COMPONENT}-${VERSION}-linux-amd64"
./"${COMPONENT}-${VERSION}-linux-amd64" --help
```

Or via plain curl, keeping the original filenames (so `sha256sum -c` works directly):

```bash
VERSION=v0.2.0
URL=https://github.com/madic-creates/claude-alert-analyzer/releases/download/$VERSION
curl -fsSL -O "$URL/k8s-analyzer-${VERSION}-linux-amd64"
curl -fsSL -O "$URL/k8s-analyzer-${VERSION}-linux-amd64.sha256"
sha256sum -c "k8s-analyzer-${VERSION}-linux-amd64.sha256"
chmod +x "k8s-analyzer-${VERSION}-linux-amd64"
```

If the operator prefers a non-versioned local filename (e.g. just `k8s-analyzer`), they need to either rename after `sha256sum -c`, or rewrite the sidecar before verification.

## Rollout

Single-step rollout — no special bootstrap:

1. Add the four new steps to `.github/workflows/build.yaml` (Set-up-Go, Compile, Upload — Step 12 collapsed into Step 11).
2. Commit + push to a feature branch, PR, merge.
3. The merge commit's `feat:` triggers a release (e.g. `v0.3.0`). The release workflow runs all original steps, then the new ones. Verify on GitHub:
   - The release page lists 4 asset files.
   - Each `.sha256` correctly verifies its companion binary (`sha256sum -c`).
   - Binary `--help` output prints normally on a Linux box.
4. Subsequent non-release commits skip the new steps via the existing `if:` guard. Confirmed by inspecting the workflow log.

## Out of Scope (Restated)

- ARM64, macOS, Windows binaries.
- Version-info embedding via `-ldflags="-X"`.
- Code signing, attestations, SBOMs, image signatures.
- Combined `SHA256SUMS` (single file with all hashes).
- Tarball wrapping (`.tar.gz`).
- Asset upload to non-GitHub locations (S3, GCS, etc.).
- Unifying Dockerfile and release-asset build flags (Dockerfile keeps current `go build` invocation; release assets add `-trimpath -ldflags="-s -w"`). Future change can converge both.
- Compatibility with GitHub's "immutable releases" feature (currently in preview). If enabled, the post-publish-upload pattern breaks and the design needs to switch to draft-first.
