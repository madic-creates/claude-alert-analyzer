# Semantic Versioning & Auto-Releases — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add automatic Conventional-Commit-driven semantic versioning that produces Git tags, GitHub Releases, and semver-tagged GHCR images on every release-worthy push to `main`.

**Architecture:** Restructure `.github/workflows/build.yaml` so the existing per-push build/push jobs are removed; image building and pushing now happens only inside a new `release` job which runs `go-semantic-release` (dry-run → build+push images → publish tag). The cleanup workflow is updated to protect semver-tagged images. Renovate is configured to emit `chore(deps):` commits explicitly. A one-time `v0.1.0` bootstrap tag avoids the default `v1.0.0` first-release behavior.

**Tech Stack:** GitHub Actions, `go-semantic-release/action`, `commit-analyzer-cz` (default plugin), `docker/setup-buildx-action`, `docker/build-push-action`, `docker/metadata-action`, `docker/login-action`, jq, GHCR, Renovate.

**Spec:** `docs/superpowers/specs/2026-05-08-semantic-versioning-design.md` — read it first; this plan does not duplicate the design rationale.

## Pin Reference (resolved during Task 1)

```
go-semantic-release/action: v1.24.1 @ 2e9dc4247a6004f8377781bef4cb9dad273a741f
semantic-release binary:    v2.31.0
commit-analyzer-cz major:        1   (use default@^1.0.0)
changelog-generator-default major: 1   (use default@^1.0.0)
condition-github major:          1   (use github@^1.0.0)
provider-github major:           1   (use github@^1.0.0)
```

**Note on binary pinning:** the action does NOT expose a `version:` input. To pin the semantic-release binary, install it explicitly in a separate step and use the `bin:` input to point at the installed path. Asset URL pattern: `https://github.com/go-semantic-release/semantic-release/releases/download/v2.31.0/semantic-release_v2.31.0_linux_amd64`.

**Note on output names:** the action exposes `outputs.version`, `outputs.version_major`, `outputs.version_minor`, `outputs.version_patch`, `outputs.version_prerelease`, `outputs.changelog`. Earlier drafts of this plan used `outputs.major`/`outputs.minor` — corrected below.

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `.semrelrc` | CREATE (repo root) | semantic-release plugin selection + custom patch/minor/major commit rules |
| `.github/workflows/build.yaml` | MODIFY (restructure) | Remove `build-k8s`/`build-checkmk` jobs; add single `release` job with dry-run/login/build-push-k8s/build-push-checkmk/publish; add `.semrelrc` to `paths`; remove top-level `concurrency`; release job has its own per-ref concurrency |
| `.github/workflows/cleanup-ghcr.yaml` | MODIFY (jq filter only) | Protect semver-tagged image versions from deletion |
| `.github/renovate.json5` | MODIFY (add settings) | Force `chore(deps):` commit prefix |
| Git tag `v0.1.0` | CREATE (one-time bootstrap, manual) | Avoid default `v1.0.0` first-release |

No code files are touched.

---

## Task 1: Look Up Pinned Versions

**Why first:** Tasks 2 and 5 reference exact pins. Document them once here so the rest of the plan uses concrete values, not "TBD".

**Files:** none (research only)

- [ ] **Step 1: Find the latest stable release of `go-semantic-release/action`**

Run:
```bash
gh release view --repo go-semantic-release/action --json tagName,targetCommitish,publishedAt
```

Note the `tagName` (e.g. `v1.23.4`) and the SHA (`targetCommitish`, full 40-char). Record both.

- [ ] **Step 2: Find the binary version that action ships**

Run:
```bash
gh api repos/go-semantic-release/action/contents/action.yml --jq .content | base64 -d | grep -A1 -E 'version|RELEASE_BIN_VERSION'
```

If the action has a `with: version:` input, you can pin a specific binary release. Visit https://github.com/go-semantic-release/semantic-release/releases and pick the latest stable (e.g. `v2.32.0`). Record it.

- [ ] **Step 3: Find current published versions of the four plugins**

Run for each:
```bash
for plugin in commit-analyzer-cz changelog-generator-default condition-github provider-github; do
  echo "=== $plugin ==="
  gh release view --repo "go-semantic-release/$plugin" --json tagName 2>/dev/null
done
```

Record the latest stable major version for each. The `.semrelrc` will pin to `^N.0.0` of the recorded major (e.g. `default@^1.0.0` if latest is 1.x).

- [ ] **Step 4: Record findings**

Append a "Pin Reference" section to this plan as a comment. Example format:

```
# Pin Reference (filled during Task 1)
# go-semantic-release/action: v1.23.4 @ <40-char-sha>
# semantic-release binary:    v2.32.0
# commit-analyzer-cz major:   1   (use default@^1.0.0)
# changelog-generator default major: 1
# condition-github major:     1
# provider-github major:      1
```

These values are inputs to Tasks 2 (.semrelrc) and 5 (build.yaml).

- [ ] **Step 5: Commit task completion**

No commit — this is research only. Move on.

---

## Task 2: Add `.semrelrc`

**Files:**
- Create: `.semrelrc`

- [ ] **Step 1: Write the config file**

Use the major versions recorded in Task 1. Replace `^1.0.0` below with the actual recorded majors if they differ.

Create `.semrelrc` at the repo root with this exact content (substituting major versions only):

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

- [ ] **Step 2: Verify it's valid JSON**

Run:
```bash
jq . .semrelrc
```

Expected: pretty-printed output, exit code 0. If `jq` errors with "parse error", fix the JSON.

- [ ] **Step 3: Commit**

```bash
git add .semrelrc
git commit -m "feat: add semantic-release config (.semrelrc)"
```

---

## Task 3: Update `cleanup-ghcr.yaml` jq filter

**Files:**
- Modify: `.github/workflows/cleanup-ghcr.yaml` (lines 51-55, the `jq -r --argjson keep ...` block)

- [ ] **Step 1: Write a fixture file capturing the corner cases**

The fixture mimics the GHCR API response: an array of `{id, created_at, tags}`. We want the filter to:
- KEEP versions with semver-shaped tags (`v0.2.6`, `0.2.6`, `0.2`) regardless of age
- DELETE older versions whose tags are only sha-shaped or `latest`-only
- DELETE untagged versions when over `KEEP_TAGGED`
- Treat the date-shaped tag `2026.5.8` as protected (false-positive accepted in spec)

Run:
```bash
cat > /tmp/versions-fixture.json <<'EOF'
[
  {"id": 1, "created_at": "2026-05-08T12:00:00Z", "tags": ["v0.2.6", "0.2.6", "0.2", "latest"]},
  {"id": 2, "created_at": "2026-05-07T12:00:00Z", "tags": ["v0.2.5", "0.2.5"]},
  {"id": 3, "created_at": "2026-05-06T12:00:00Z", "tags": ["v0.2.4"]},
  {"id": 4, "created_at": "2026-05-05T12:00:00Z", "tags": ["v0.2.3"]},
  {"id": 5, "created_at": "2026-05-04T12:00:00Z", "tags": ["v0.2.2"]},
  {"id": 6, "created_at": "2026-05-03T12:00:00Z", "tags": ["v0.2.1"]},
  {"id": 7, "created_at": "2026-05-02T12:00:00Z", "tags": ["v0.2.0"]},
  {"id": 8, "created_at": "2026-05-01T12:00:00Z", "tags": ["v0.1.0"]},
  {"id": 9, "created_at": "2026-04-30T12:00:00Z", "tags": ["abc1234"]},
  {"id": 10, "created_at": "2026-04-29T12:00:00Z", "tags": ["def5678"]},
  {"id": 11, "created_at": "2026-04-28T12:00:00Z", "tags": ["ghi9012"]},
  {"id": 12, "created_at": "2026-04-27T12:00:00Z", "tags": ["jkl3456"]},
  {"id": 13, "created_at": "2026-04-26T12:00:00Z", "tags": []},
  {"id": 14, "created_at": "2026-04-25T12:00:00Z", "tags": ["2026.5.8"]}
]
EOF
```

The fixture is sorted newest-first like the real `gh api ... | sort_by(.created_at) | reverse` output.

- [ ] **Step 2: Run the new filter against the fixture and verify expected output**

Run with `KEEP_TAGGED=3` (small enough that the test is interesting):

```bash
jq -r --argjson keep 3 '
  def semver_protected:
    any(.tags[]?; test("^(v?[0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+\\.[0-9]+)$"));
  [ .[] | select(semver_protected | not) ] as $candidates
  | ($candidates[$keep:] // [])
  | .[] | "\(.id)\t\(.created_at)\t\(.tags | join(","))"
' /tmp/versions-fixture.json
```

Expected output (only sha-tagged and untagged versions, beyond top 3 of unprotected):

```
12	2026-04-27T12:00:00Z	jkl3456
13	2026-04-26T12:00:00Z
```

Verify:
- IDs 1-8 (semver-tagged) and 14 (`2026.5.8` matches the regex) are **not** in the output → kept.
- IDs 9, 10, 11 (top 3 sha-tagged) are kept by `KEEP_TAGGED=3`.
- IDs 12 (older sha-tagged) and 13 (untagged) appear in the deletion list.

If the output differs, the regex or the filter is wrong — fix and re-run.

- [ ] **Step 3: Apply the filter change to `cleanup-ghcr.yaml`**

Open `.github/workflows/cleanup-ghcr.yaml`. Find the existing block at lines 49-55:

```yaml
          # Candidates: all untagged + tagged beyond the KEEP_TAGGED most recent.
          # 'latest' sits on the newest push, so it is always in the kept top-N.
          jq -r --argjson keep "$KEEP_TAGGED" '
            ([.[] | select(.tags | length == 0)]
            + [.[] | select(.tags | length > 0)][$keep:])
            | .[] | "\(.id)\t\(.created_at)\t\(.tags | join(","))"
          ' versions.json > to_delete.tsv
```

Replace it with:

```yaml
          # Protected: any version with a semver-shaped tag (v0.2.6, 0.2.6, 0.2).
          # Date-shaped tags like 2026.5.8 also match — accepted false-positive
          # toward retention. Unprotected versions (sha-tagged, untagged,
          # latest-only) follow KEEP_TAGGED.
          jq -r --argjson keep "$KEEP_TAGGED" '
            def semver_protected:
              any(.tags[]?; test("^(v?[0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+\\.[0-9]+)$"));
            [ .[] | select(semver_protected | not) ] as $candidates
            | ($candidates[$keep:] // [])
            | .[] | "\(.id)\t\(.created_at)\t\(.tags | join(","))"
          ' versions.json > to_delete.tsv
```

- [ ] **Step 4: Verify yaml is still valid**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/cleanup-ghcr.yaml'))"
```

Expected: no output, exit code 0. If errors, fix the indentation.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/cleanup-ghcr.yaml
git commit -m "fix(ci): protect semver-tagged images in GHCR cleanup"
```

---

## Task 4: Update `.github/renovate.json5`

**Files:**
- Modify: `.github/renovate.json5`

- [ ] **Step 1: Read the current file**

```bash
cat .github/renovate.json5
```

Note the existing top-level keys to avoid duplication.

- [ ] **Step 2: Add semantic-commit settings**

Open `.github/renovate.json5` and add these three top-level keys (anywhere inside the root object). If a `extends` array already lists `:semanticCommitTypeAll(...)` or similar, leave it but still add explicit keys:

```json5
{
  // ... existing keys ...
  semanticCommits: "enabled",
  semanticCommitType: "chore",
  semanticCommitScope: "deps"
}
```

The exact placement (alphabetical or existing-style) follows whatever convention the file already uses. Trailing commas in json5 are fine.

- [ ] **Step 3: Validate the file is parseable as json5**

If `npx` is available:

```bash
npx --yes json5 -V .github/renovate.json5 2>&1 || echo "json5 cli not available"
```

Otherwise just verify by visual inspection that braces match and there are no obvious syntax errors. (Renovate validates the file at PR-creation time anyway.)

- [ ] **Step 4: Commit**

```bash
git add .github/renovate.json5
git commit -m "ci(renovate): force chore(deps): commit prefix for semantic releases"
```

---

## Task 5: Restructure `.github/workflows/build.yaml`

This is the largest task. Several logical changes happen in one file rewrite. We'll do them as one atomic edit (because the old build jobs and the new release job are coupled via concurrency and paths), but verify yaml syntax + GitHub Actions schema after each edit.

**Files:**
- Modify: `.github/workflows/build.yaml` (full rewrite of jobs section, header tweaks)

- [ ] **Step 1: Read current state**

```bash
cat .github/workflows/build.yaml
```

Confirm the current file has these elements (they all change):
- `paths:` filter listing 6 entries
- top-level `concurrency: group: ${{ github.workflow }}, cancel-in-progress: false`
- `permissions: contents: read, packages: write`
- jobs: `test`, `lint`, `build-k8s`, `build-checkmk`

- [ ] **Step 2: Write the new file**

Replace the entire contents of `.github/workflows/build.yaml` with the following. Substitute:
- `{{ACTION_SHA}}` with the 40-char SHA recorded in Task 1
- `{{ACTION_VERSION_TAG}}` with the action tag (e.g. `v1.23.4`) — used as a comment for human readers
- `{{BIN_VERSION}}` with the binary version (e.g. `v2.32.0`) — used in the `with: version:` input

```yaml
---
name: Build Analyzer Images

on:
  push:
    branches: [main]
    paths:
      - "cmd/**"
      - "internal/**"
      - "Dockerfile"
      - "go.mod"
      - "go.sum"
      - ".github/workflows/build.yaml"
      - ".semrelrc"
  workflow_dispatch:

permissions:
  contents: read
  packages: write

env:
  REGISTRY: ghcr.io/${{ github.repository_owner }}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with:
          go-version-file: go.mod
      - run: go vet ./...
      - run: go test -race -count=1 ./...

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with:
          go-version-file: go.mod
      - uses: golangci/golangci-lint-action@v9

  release:
    needs: [test, lint]
    runs-on: ubuntu-latest
    permissions:
      contents: write     # create tag + GitHub Release
      packages: write     # push images to GHCR
    concurrency:
      group: release-${{ github.ref }}
      cancel-in-progress: false
    steps:
      - name: Checkout (full history + tags)
        uses: actions/checkout@v6
        with:
          fetch-depth: 0
          fetch-tags: true

      - name: Install pinned semantic-release binary
        run: |
          curl -fsSL \
            https://github.com/go-semantic-release/semantic-release/releases/download/v2.31.0/semantic-release_v2.31.0_linux_amd64 \
            -o /tmp/semantic-release
          chmod +x /tmp/semantic-release
          /tmp/semantic-release --version

      - name: Determine next version (dry-run)
        id: semrel-dry
        # go-semantic-release/action v1.24.1
        uses: go-semantic-release/action@2e9dc4247a6004f8377781bef4cb9dad273a741f
        with:
          bin: /tmp/semantic-release
          dry: true
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Set up Buildx
        if: steps.semrel-dry.outputs.version != ''
        uses: docker/setup-buildx-action@v4

      - name: Log in to GHCR
        if: steps.semrel-dry.outputs.version != ''
        uses: docker/login-action@v4
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Compute image tags (k8s)
        if: steps.semrel-dry.outputs.version != ''
        id: meta-k8s
        uses: docker/metadata-action@v6
        with:
          images: ${{ env.REGISTRY }}/claude-alert-kubernetes-analyzer
          tags: |
            type=raw,value=v${{ steps.semrel-dry.outputs.version }}
            type=raw,value=${{ steps.semrel-dry.outputs.version }}
            type=raw,value=${{ steps.semrel-dry.outputs.version_major }}.${{ steps.semrel-dry.outputs.version_minor }}
            type=raw,value=latest

      - name: Build & push k8s-analyzer
        if: steps.semrel-dry.outputs.version != ''
        uses: docker/build-push-action@v7
        with:
          context: .
          target: k8s-analyzer
          push: true
          tags: ${{ steps.meta-k8s.outputs.tags }}
          labels: ${{ steps.meta-k8s.outputs.labels }}
          cache-from: type=gha,scope=k8s-analyzer
          cache-to: type=gha,scope=k8s-analyzer,mode=max

      - name: Compute image tags (checkmk)
        if: steps.semrel-dry.outputs.version != ''
        id: meta-checkmk
        uses: docker/metadata-action@v6
        with:
          images: ${{ env.REGISTRY }}/claude-alert-checkmk-analyzer
          tags: |
            type=raw,value=v${{ steps.semrel-dry.outputs.version }}
            type=raw,value=${{ steps.semrel-dry.outputs.version }}
            type=raw,value=${{ steps.semrel-dry.outputs.version_major }}.${{ steps.semrel-dry.outputs.version_minor }}
            type=raw,value=latest

      - name: Build & push checkmk-analyzer
        if: steps.semrel-dry.outputs.version != ''
        uses: docker/build-push-action@v7
        with:
          context: .
          target: checkmk-analyzer
          push: true
          tags: ${{ steps.meta-checkmk.outputs.tags }}
          labels: ${{ steps.meta-checkmk.outputs.labels }}
          cache-from: type=gha,scope=checkmk-analyzer
          cache-to: type=gha,scope=checkmk-analyzer,mode=max

      - name: Publish Git tag + GitHub Release
        if: steps.semrel-dry.outputs.version != ''
        # go-semantic-release/action v1.24.1
        uses: go-semantic-release/action@2e9dc4247a6004f8377781bef4cb9dad273a741f
        with:
          bin: /tmp/semantic-release
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

Notes about this content:
- The top-level `concurrency:` block from the old file is **removed**. Test/lint run unconstrained per push; release-job has its own per-ref concurrency block.
- `outputs.major`, `outputs.minor`, `outputs.version` are exposed by `go-semantic-release/action` (see action.yml). The minor-stream tag uses `${major}.${minor}`.
- Two separate `metadata-action` invocations (one per image) keep tags scoped to the right image. They are not actually expensive; they just compute label/tag strings.
- Cache scopes are per-image (`k8s-analyzer` and `checkmk-analyzer`) — the spec calls this out in "Workflow Architecture" Step 3/4.
- If Task 1 found that `go-semantic-release/action` does NOT support a `with: version:` input, replace those `uses:` blocks with a manual `curl`-install step that fetches the binary at `{{BIN_VERSION}}` and runs it. The fallback procedure is in spec §"Tooling".

- [ ] **Step 3: Verify yaml syntax**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/build.yaml'))"
```

Expected: no output, exit code 0. If errors, fix indentation/quoting.

- [ ] **Step 4: Verify GitHub Actions schema (best-effort)**

If `actionlint` is installed:

```bash
actionlint .github/workflows/build.yaml
```

Otherwise skip — GitHub validates on push and we'll catch errors at PR time. If errors mention unknown `outputs.major`/`minor`, fall back to plain `outputs.version` and parse it client-side in a script step (e.g. `MINOR=$(echo "$VERSION" | cut -d. -f1-2)`).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/build.yaml
git commit -m "feat(ci): replace per-push image build with semantic-release flow"
```

---

## Task 6: Open PR, Bootstrap, Merge, Verify

This task contains manual steps that interact with GitHub and the registry. It can't be automated by a subagent — execute these yourself.

**Files:** none locally; all state changes are remote.

- [ ] **Step 1: Push the branch and open a draft PR**

```bash
git push -u origin <feature-branch-name>
gh pr create --draft --title "feat(ci): semantic versioning and auto-releases" \
  --body "$(cat <<'EOF'
Implements docs/superpowers/specs/2026-05-08-semantic-versioning-design.md.

## Summary
- Add .semrelrc (go-semantic-release config with custom commit rules incl. chore(deps): → patch).
- Restructure build.yaml: remove build-k8s/build-checkmk jobs; add release job that does dry-run → build+push → publish atomically.
- Update cleanup-ghcr.yaml to protect semver-tagged image versions from deletion.
- Update renovate.json5 to force chore(deps): commit prefix.

## Test plan
- [ ] CI green on draft PR (test+lint, no release attempt yet because branch != main).
- [ ] After merge: first run on main creates v0.X.Y tag, GHCR images, GitHub Release.
- [ ] Subsequent non-release commit (e.g. chore: tidy): test+lint only, no release.
- [ ] Subsequent fix: commit on a build-relevant path: bumps patch.

EOF
)"
```

- [ ] **Step 2: Wait for PR CI to pass**

`test` and `lint` jobs run on the draft PR's branch (because they trigger on `push`, not `push: branches: main` — actually wait, current trigger is `push: branches: [main]`. Branch pushes only trigger on main).

**Important:** the workflow only triggers on pushes to `main`. PR branch pushes do **not** trigger this workflow. To test on a feature branch before merge, temporarily add the PR branch to `branches:` in `build.yaml` (one extra entry, e.g. `[main, ci/test-semantic-release]`), or rely on the merge to surface any issue.

If you want pre-merge confidence: add the branch name to `branches:` temporarily, push, watch CI, then remove the extra entry before merge.

- [ ] **Step 3: Just before merging — bootstrap the initial Git tag**

This is the one-time bootstrap. It MUST happen before the PR merges, otherwise the first run computes v1.0.0 instead of v0.1.x.

```bash
git fetch origin main
git tag v0.1.0 origin/main         # tag the current main HEAD as v0.1.0
git push origin v0.1.0             # explicit ref, not --tags
```

Verify the tag is on the remote:

```bash
gh api repos/:owner/:repo/git/refs/tags/v0.1.0
```

Expected: a JSON object pointing to a SHA. If 404, the push failed — investigate.

- [ ] **Step 4: Mark PR ready, get review/approval, merge**

```bash
gh pr ready
# wait for review/approval per project rules
gh pr merge --squash    # or --merge / --rebase per project convention
```

- [ ] **Step 5: Watch the first release run**

```bash
gh run watch
```

The workflow should:
1. Run `test` + `lint` jobs (parallel).
2. Start the `release` job.
3. Dry-run step: `outputs.version` populated (or empty if the merge commit doesn't trigger any release rule — in which case nothing further happens, which is fine).
4. If version populated: setup buildx, login, build + push both images, publish.

If the run fails at any step, read the log and consult spec §"Edge Cases" for failure-mode interpretation. Most rerun-safe failure paths are documented.

- [ ] **Step 6: Verify GHCR tags**

```bash
for img in claude-alert-kubernetes-analyzer claude-alert-checkmk-analyzer; do
  echo "=== $img ==="
  gh api "/users/${{ github.repository_owner }}/packages/container/$img/versions" \
    --jq '.[0:5] | .[] | {tags: .metadata.container.tags, created: .created_at}'
done
```

Expected: the newest version of each image carries 4 tags: `vX.Y.Z`, `X.Y.Z`, `X.Y`, `latest`. All sharing the same digest (visible via `docker buildx imagetools inspect`).

- [ ] **Step 7: Verify GitHub Releases page**

```bash
gh release view --json tagName,name,body
```

Expected: a release with the new tag name, body containing grouped notes (Features / Bug Fixes / Performance) for the commits since `v0.1.0`.

- [ ] **Step 8: Verify non-release commit behavior (post-rollout)**

When the next commit on a build-relevant path lands that has no release-triggering type (e.g. `chore: tidy logging`), watch its run:

```bash
gh run list --branch main --limit 5
```

Expected: `test` + `lint` succeed; the `release` job's first step (dry-run) completes with empty `outputs.version`; subsequent steps are skipped via the `if:` guards. No new tag, no new release, no new images. Workflow stays green.

- [ ] **Step 9: Verify cleanup-ghcr behavior on next scheduled run**

The cleanup workflow runs Sundays 04:00 UTC. To verify before then, run it manually with `dry_run: true`:

```bash
gh workflow run cleanup-ghcr.yaml -f dry_run=true
gh run watch
```

Expected: in the dry-run output, no semver-tagged versions appear in the deletion list. Sha-tagged or untagged backlog (from before this rollout) may appear — that's correct behavior.

---

## Self-Review

1. **Spec coverage:** every spec section is touched by a task. `.semrelrc` (Task 2), `cleanup-ghcr.yaml` (Task 3), Renovate (Task 4), build.yaml restructure (Task 5), bootstrap+verify (Task 6). Pin reference researched (Task 1). No gaps.
2. **Placeholder scan:** the only `{{...}}` placeholders are in Task 5's workflow yaml, which Task 1 explicitly fills in. No "TBD" or "implement later" copy.
3. **Type/name consistency:** `outputs.version`, `outputs.major`, `outputs.minor` are referenced consistently. The `meta-k8s` / `meta-checkmk` step IDs are referenced exactly where needed. Cache scopes use the same image names as the targets.
4. **Trade-offs documented in spec, not duplicated here:** atomicity caveat, concurrency tradeoff, regex false-positives. The plan refers to spec sections for rationale.

---

## Notes for the Implementing Engineer

- The Dockerfile and Go code are **not** modified by this plan. If a release commit requires a change there, it's separate.
- If the first live run on `main` fails at the publish step, reruns are safe (spec §"Atomicity"). Don't try to manually create the tag or release — let the workflow rerun do it.
- If you need to roll back: delete the tag (`git push origin :v<version>`), delete the GitHub Release (`gh release delete v<version>`), and consider whether to delete the GHCR images (usually leave them — they're orphans but harmless). The next push will re-attempt the same release.
- Renovate may emit its first `chore(deps):` PR within hours of merge. That PR's merge commit will trigger a patch release — expected behavior.
