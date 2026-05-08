# Semantic Versioning & Auto-Releases

**Date:** 2026-05-08
**Status:** Approved (revised after three codex reviews + scope simplification; awaiting implementation plan)
**Scope:** Add automatic semantic-version tagging, GitHub Releases, and semver-tagged container images, driven by Conventional Commits on `main`. Container images are produced **only on release commits**.

## Goal

Every push to `main` whose changes touch build-relevant paths (`cmd/**`, `internal/**`, `Dockerfile`, `go.mod`, `go.sum`, `.github/workflows/build.yaml`, `.semrelrc`) runs `test` + `lint`. Pushes that only touch ignored paths (e.g. `docs/**`, `.github/renovate.json5`, this spec file) don't trigger the workflow at all — see "Path Filters". On triggering commits that warrant a release (per the rules below), the workflow additionally:

1. Determines the next semver version from Conventional Commit messages.
2. Builds and pushes both container images tagged with the new semver tags **and** `latest`.
3. Creates a Git tag and a GitHub Release with auto-generated notes.

Steps 2 and 3 are sequenced **build-push-before-publish** so that a published GitHub Release always implies semver-tagged images exist (see "Atomicity" below).

Triggering non-release commits (`chore:` without `(deps)`, `obs:`, `style:`, `refactor:` not configured for patch — anything not in the patch/minor/major release rules but that still touches build-relevant paths) produce no images, no tags, no GitHub Release. Pure `docs:` and `test:` commits typically don't trigger at all.

`<short-sha>`-tagged container images are no longer produced. `latest` no longer follows main HEAD; it always points to the most recent release.

**Cadence:** per-commit when push rate is below release-job throughput. When pushes arrive faster, intermediate commits are bundled — semantic-release picks the highest-applicable bump across all commits since the last tag and produces a single release. This is a **safe collapse**, not a correctness issue. No release-PR step.

## Tooling

**Selected:** [`go-semantic-release`](https://github.com/go-semantic-release/semantic-release) — Go-native, single binary, no Node.js dependency.

**GH Action:** `go-semantic-release/action`, **pinned by commit SHA**. Note that pinning the action SHA only freezes the Node.js wrapper around the binary — the action downloads the `semantic-release` binary at runtime and (without further config) picks the latest. The implementation phase pins the binary version too, either via the action's input (e.g. `with: version: x.y.z`) if available, or by replacing the action with explicit `curl`-install of a known binary release in the workflow step.

**Commit Analyzer:** `commit-analyzer-cz` (default), with custom rules (see below). Plugin name pinned via `default@^1.0.0` syntax.

**Provider:** GitHub.

**Changelog Generator:** default — output goes into the GitHub Release body. **No** `CHANGELOG.md` in the repo.

### Known limitation: breaking-change handling

`commit-analyzer-cz` distinguishes two kinds of breaking-change marker, and only one is fully configurable:

- **Footer `BREAKING CHANGE:` / `BREAKING CHANGES:`** — always forces a major bump; explicitly **not configurable** (documented analyzer limitation).
- **Header `!` modifier (`feat!:`, `refactor!:`, etc.)** — major-by-default because `major_release_rules` defaults to `*!`, but that rule *is* configurable (could be cleared, restricted, or replaced).

Accepted convention until v1.0: write **neither** `BREAKING CHANGE` footers nor `!`-suffixed types. Larger reworks ship as plain `feat:` and bump minor. The first deliberate breaking-change commit (footer or `!`) is the conscious jump to v1.0.0.

## Versioning Rules

| Commit type | Bump | Example |
|---|---|---|
| `fix:` | patch | v0.2.5 → v0.2.6 |
| `chore(deps):` (Renovate) | patch | v0.2.5 → v0.2.6 |
| `perf:` | patch | v0.2.5 → v0.2.6 |
| `refactor:` | patch | v0.2.5 → v0.2.6 |
| `feat:` | minor | v0.2.5 → v0.3.0 |
| `BREAKING CHANGE:` footer / `feat!:` etc. | major (= deliberate v1.0.0 jump) | v0.2.5 → v1.0.0 |
| `chore:` (without `(deps)`), `docs:`, `test:`, `obs:`, `style:` | no release | — |

**Pre-1.0 convention:** no `BREAKING CHANGE` footer, no `!` modifier. The first true breaking change is the conscious step to v1.0.

**Initial tag:** `v0.1.0`, created manually as a one-time bootstrap before activating the workflow:

```bash
git tag v0.1.0
git push origin v0.1.0    # explicit ref, not --tags
```

Without an existing tag, `semantic-release` would emit `v1.0.0` on the first run.

## Configuration File

New file: `.semrelrc` (repo root):

```json
{
  "plugins": {
    "commit-analyzer": {
      "name": "default@^1.0.0",
      "options": {
        "patch_release_rules": "fix,perf,refactor,chore(deps)",
        "minor_release_rules": "feat",
        "major_release_rules": "*!"
      }
    },
    "ci-condition":        { "name": "github@^1.0.0" },
    "provider":            { "name": "github@^1.0.0" },
    "changelog-generator": { "name": "default@^1.0.0" }
  }
}
```

Plugin versions are pinned to a major range (`^1.0.0` allows `>=1.0.0 <2.0.0`) to avoid breaking-change auto-upgrades. Implementation phase verifies the exact published versions and tightens the constraint if needed. No `package.json`, no `package-lock.json`, no Node setup.

## Workflow Architecture

`build.yaml` is restructured. The existing `build-k8s` and `build-checkmk` jobs are **removed** (they previously built and pushed images on every main push). Their build logic moves into the new `release` job, which only runs and pushes when a release is happening.

```
push to main
  ├─► test                    (existing, per-SHA)
  ├─► lint                    (existing, per-SHA)
  │
  └─► release  (NEW, needs: [test, lint], per-ref serialized)
        Step 0: actions/checkout@v6 with fetch-depth: 0, fetch-tags: true
                Required: semantic-release needs full history + tags to
                locate the last release tag and walk subsequent commits.

        Step 1 (dry-run):
                go-semantic-release/action with `dry: true`
                → outputs.version  (e.g. "0.2.6" or "")
                No tag created, no GitHub Release published.

        Step 2 (only if outputs.version != ""):  Set up Buildx + GHCR login
                docker/setup-buildx-action  (required for `cache: type=gha`)
                docker/login-action — release job has its own session.

        Step 3 (only if outputs.version != ""):  Build + push k8s-analyzer
                docker/build-push-action with target: k8s-analyzer
                tags from docker/metadata-action:
                  type=raw,value=v${VERSION}
                  type=raw,value=${VERSION}
                  type=raw,value=${MINOR}            (e.g. "0.2")
                  type=raw,value=latest
                push: true
                cache-from: type=gha,scope=k8s-analyzer
                cache-to:   type=gha,scope=k8s-analyzer,mode=max

        Step 4 (only if outputs.version != ""):  Build + push checkmk-analyzer
                Same pattern, target: checkmk-analyzer.
                cache-from: type=gha,scope=checkmk-analyzer
                cache-to:   type=gha,scope=checkmk-analyzer,mode=max
                (per-image scopes prevent the second image's cache-to from
                 overwriting the first's — `gha` backend defaults to a single
                 `scope=buildkit` bucket otherwise.)

        Step 5 (only if outputs.version != ""):  Publish release
                go-semantic-release/action without dry-run
                → creates Git tag + GitHub Release with auto-generated notes
```

Non-release commits stop after `test` + `lint`: dry-run returns empty, no GHCR login, no build, no publish.

### Why this structure

- **No images for non-release commits**: `<short-sha>` and HEAD-tracking-`latest` are gone. Image builds happen only when the result is a tagged release.
- **Build-push before publish**: if the docker build/push fails, no Git tag and no GitHub Release exist yet — a workflow rerun re-runs the dry-run, gets the same version, retries the build, then publishes. From the user-visible side: a published `vX.Y.Z` Release always implies the images exist under that tag.
- **CI verification simplified**: docker-build breakage is caught when the first release commit lands. `test` + `lint` continue to gate every commit. Accepted trade-off: a base-image break may go unnoticed until the next release commit, but the main lever to detect it is `test`/`lint` plus the release-job log itself.
- **Same job builds and publishes**: avoids inter-job state passing for the version, simplifies failure isolation.

### Atomicity

The order (dry → build/push → publish) ensures rerun-safety from the user-visible side:

- **Build/push fails after dry-run** ⇒ no Git tag, no GitHub Release. Rerun: dry-run returns the same version, build retried (cache hits where possible), push proceeds, publish runs.
- **Publish fails after build/push** ⇒ images carry semver + `latest` tags, GitHub Release missing. Rerun: dry-run returns the same version (no Git tag exists yet), build runs again, push overwrites the just-pushed tags, publish retries.

A Git tag / GitHub Release is only created after both image pushes succeed, so the only state operators can observe is consistent: no `vX.Y.Z` tag without corresponding semver-tagged images.

**Caveat — digest stability across reruns.** The Dockerfile pins base images by tag (not digest) and uses `apk add` against mutable indexes, so a rebuild executed days later may produce a slightly different digest from the original. If a partial run pushed image-A under `v0.2.6` and a later rerun rebuilds and pushes image-B under the same tag, the tag now points to image-B and image-A becomes an orphaned digest. The source code is the same, but the image content drifts with whatever Alpine/Go upstream changed in the meantime. The previous design (round 2) avoided this via `imagetools create` from a known sha-tagged manifest; with sha tags removed, full digest stability would require digest-pinning base images and version-pinning all `apk` packages — out of scope here. In practice the only window where an operator could observe drift is between a partial run and its rerun, before the GitHub Release publishes — usually minutes.

### Release-job permissions

```yaml
permissions:
  contents: write    # create tag + release
  packages: write    # push images to GHCR
```

`issues: write` is not configured: the `provider-github` plugin only creates refs and releases; it does not comment on closed issues. `id-token: write` is **not** required for this design (would only become relevant for image signing or attestations, which are out of scope).

### Concurrency

The existing top-level `concurrency: group: ${{ github.workflow }}, cancel-in-progress: false` is **removed**. With the simplified flow, only the release job needs serialization:

```yaml
jobs:
  release:
    concurrency:
      group: release-${{ github.ref }}
      cancel-in-progress: false
    ...
```

**Why ref-stable serialization:** prevents a race where two concurrent SHAs both compute the *same* next version (e.g. both `v0.2.6` from a `v0.2.5` base) and one publishes the tag pointing at SHA-A while the other pushes images for SHA-B's manifest under the same `v0.2.6` / `latest` tags — silent divergence between Git and registry.

`test` and `lint` run unconstrained per push (full parallelism) — no race risk because they don't write anything externally observable.

**Trade-off — release bundling:** GitHub queues at most one running and one pending release per group; subsequent pendings replace older pendings. So a burst of N rapid pushes produces *fewer* than N releases — semantic-release on the surviving pending run picks up all bundled commits and emits a single bump. This is a safe collapse: every push runs CI, every commit's content is reflected in *some* later release.

## Image Tagging

For both `claude-alert-kubernetes-analyzer` and `claude-alert-checkmk-analyzer`, tags are produced **only on release commits**:

| Tag | When | Purpose |
|---|---|---|
| `vX.Y.Z` (e.g. `v0.2.6`) | only on release commits | Exact release version (with `v` prefix) |
| `X.Y.Z` (e.g. `0.2.6`) | only on release commits | Same, no `v` (registry convention) |
| `X.Y` (e.g. `0.2`) | only on release commits | Minor stream pointer (auto-rolls forward on patches within the minor) |
| `latest` | only on release commits | Most recent stable release |

All four tags share the digest of the freshly built release-time manifest.

The current Dockerfile and build are single-platform (`linux/amd64`). Multi-arch support is out of scope.

## GitHub Release Content

Auto-generated by `changelog-generator-default`:

- **Title:** `v0.2.6`
- **Body:** grouped sections (`### Features`, `### Bug Fixes`, `### Performance`, etc.) for all relevant commits since the last tag.
- **No asset attachments** — the GHCR images are the deliverables.

## Cleanup Workflow Update

The existing `cleanup-ghcr.yaml` keeps the `KEEP_TAGGED=10` most recently created tagged versions and unconditionally deletes the rest. With the new design, the only tags ever created are semver-shaped (`v0.2.6`, `0.2.6`, `0.2`, `latest`). After enough releases, older versions would be evicted.

**Required change:** rewrite the `jq` filter to **exclude semver-tagged images from deletion** unconditionally, then apply `KEEP_TAGGED` only to the unprotected remainder. Reference implementation:

```jq
jq -r --argjson keep "$KEEP_TAGGED" '
  def semver_protected:
    any(.tags[]?; test("^(v?[0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+\\.[0-9]+)$"));
  [ .[] | select(semver_protected | not) ] as $candidates
  | ($candidates[$keep:] // [])
  | .[] | "\(.id)\t\(.created_at)\t\(.tags | join(","))"
' versions.json > to_delete.tsv
```

- Versions whose tag list contains any tag matching `^(v?N.N.N|N.N)$` are kept indefinitely (e.g. `v0.2.6`, `0.2.6`, `0.2`).
- Unprotected versions (untagged manifest revisions, plus the `latest`-only tagged versions whose `latest` was rotated to newer releases) follow `KEEP_TAGGED`.
- `latest` itself is naturally always among the most recent — no explicit protection needed.

**Regex false-positive note:** the protective regex also matches date-shaped tags like `2026.5.8`. The false-positive direction is *retention* (we keep too much, never too little), which is fail-safe.

This change is in-scope and lands in the same PR as the release-workflow changes, otherwise the first cleanup run after rollout could destroy release images.

## Path Filters

Update `paths:` in the workflow to also include `.semrelrc`, so changes to release rules trigger the workflow:

```yaml
paths:
  - "cmd/**"
  - "internal/**"
  - "Dockerfile"
  - "go.mod"
  - "go.sum"
  - ".github/workflows/build.yaml"
  - ".semrelrc"          # NEW
```

`cleanup-ghcr.yaml` and `renovate.json5` deliberately stay out of the build trigger — they don't need to fire releases.

**Known gap:** docs-only and test-only commits do not trigger the build (and therefore not the release). This is intentional. If a `feat:` commit ever ships exclusively under `docs/**` (degenerate case), it will not produce a release; that's accepted.

## Renovate Configuration

`.github/renovate.json5` does not currently declare semantic-commit settings. The `chore(deps):` patch rule depends on Renovate using exactly that prefix. Make it explicit:

```json5
{
  semanticCommits: "enabled",
  semanticCommitType: "chore",
  semanticCommitScope: "deps"
}
```

Without this, future Renovate updates may silently change commit format and break the patch-release rule.

## Edge Cases

- **Triggering commits without release rule** (`chore:` without `(deps)`, `obs:`, `style:`, `refactor:` configured to no bump, etc., that touch build-relevant paths): test + lint run; dry-run returns empty; no GHCR login, no build, no publish. Workflow stays green.
- **Commits that don't touch build-relevant paths** (e.g. pure `docs:`, `.github/renovate.json5`-only edits): workflow doesn't trigger at all. No CI feedback for that push.
- **Multiple commits in one push** (e.g. branch merge): semantic-release picks the highest applicable bump across all commits since the last tag. One `feat:` + three `fix:` ⇒ a single minor release.
- **Re-runs / force-push**: dry-run inspects the latest tag and returns empty if a tag for the current state already exists; no double-release on retry.
- **Test or lint failure**: release job is blocked by `needs:` and never runs. Pending commits roll into the next successful release.
- **Build/push fails after dry-run**: rerun is safe — same version, retried build, then publish.
- **Publish fails after build/push**: rerun is safe — dry-run returns the same version (no Git tag yet), rebuild + re-push (digest may drift if base images changed in the meantime; see Atomicity caveat), publish retries. Final state is consistent.
- **Initial tag missing**: without `v0.1.0` in place, the first run would emit `v1.0.0`. Mitigation: `git push origin v0.1.0` as a one-time bootstrap.
- **Renovate-avalanche / push burst**: due to ref-stable release-job concurrency, rapid pushes may bundle into fewer releases than commits. Each commit's content lands in *some* release; no commit is silently dropped.
- **Docker-build breakage on a release commit**: release job fails at the build step, no tag, no GitHub Release. Visible in CI as a failed workflow. Fix the build, push, retry.
- **Docker-build breakage on a non-release commit**: not detected by the workflow (no build runs). Will surface on the next release commit. Accepted trade-off of the simplified flow.

## Rollout

1. **Bootstrap tag**: `git tag v0.1.0 && git push origin v0.1.0`.
2. **PR**: in a single PR, apply the following changes:
   - Add `.semrelrc`.
   - Restructure `build.yaml`: remove `build-k8s` and `build-checkmk` jobs; remove top-level `concurrency`; add a single `release` job with checkout/dry-run/login/build-push-k8s/build-push-checkmk/publish steps and per-ref concurrency; update `paths:` to include `.semrelrc`.
   - Update `cleanup-ghcr.yaml` (semver-tag protection via the jq filter above).
   - Update `.github/renovate.json5` (explicit semantic commits).
3. **Merge**: first live release run.
4. **Verify**:
   - GHCR shows tags `v<version>`, `<version>`, `<minor>`, `latest` for both images, all sharing the same digest.
   - GitHub Releases page shows the new entry with grouped notes.
   - A subsequent non-release commit on build-relevant paths (e.g. `chore: tidy logging`) triggers test+lint only — no images, no release. A docs-only commit doesn't trigger the workflow at all.

## Out of Scope (for this design)

- Per-component versioning (k8s vs checkmk independent cadence) — explicitly chosen against in favor of one shared repo version.
- Pre-release / beta channels (`v1.0.0-beta.1`).
- Maintaining `CHANGELOG.md` inside the repo.
- Helm chart or Kustomize manifest updates triggered by new versions.
- Image signing / SBOM attestations (would require `id-token: write` and tooling beyond this design).
- Multi-arch builds.
- Per-commit reproducible image deployment via `<short-sha>` tags (deliberate scope reduction; only release-tagged images are deployable).
- Early Docker-build verification on non-release commits (accepted trade-off in favor of workflow simplicity).
