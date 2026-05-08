# Release Binaries — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing `release` job in `.github/workflows/build.yaml` to compile both analyzer binaries for `linux/amd64` and attach them (with per-file SHA-256 sidecars) to the GitHub Release.

**Architecture:** Three new steps appended to the `release` job, each guarded by `if: steps.semrel-dry.outputs.version != ''`. Steps are: (1) `actions/setup-go@v6`, (2) a single shell step that builds both binaries with `-trimpath -ldflags="-s -w"` and emits per-file `.sha256` sidecars, (3) `gh release upload` with `--clobber`. Runs only on release commits; non-release pushes skip via the existing guard.

**Tech Stack:** GitHub Actions, `actions/setup-go@v6`, plain `go build`, `sha256sum`, `gh release upload`.

**Spec:** `docs/superpowers/specs/2026-05-08-release-binaries-design.md` — read it first; this plan does not duplicate the design rationale.

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `.github/workflows/build.yaml` | MODIFY (append 3 steps to existing `release` job) | Compile both analyzer binaries linux/amd64, generate SHA-256 sidecars, upload to GitHub Release |

No new files. No code changes outside CI.

---

## Task 1: Create feature branch

**Why first:** changes happen on a branch, not directly on main. Quick git setup.

**Files:** none.

- [ ] **Step 1: Verify clean working tree**

Run:
```bash
git status --short
```

Expected: empty output, OR only the unrelated `.gitignore`/Node-leftover untracked files. No staged or modified files in the workflow file.

If anything in `.github/workflows/build.yaml` is dirty, stop and resolve before continuing.

- [ ] **Step 2: Switch to main and pull latest**

Run:
```bash
git checkout main
git pull origin main
```

Expected: HEAD on main, up to date with origin.

- [ ] **Step 3: Create feature branch**

Run:
```bash
git checkout -b feat/release-binaries
```

Expected: switched to new branch `feat/release-binaries`.

---

## Task 2: Add the three new workflow steps

**Files:**
- Modify: `.github/workflows/build.yaml` (append after the existing "Publish Git tag + GitHub Release" step at line 137-143)

- [ ] **Step 1: Read the tail of the current build.yaml to confirm anchor**

Run:
```bash
sed -n '136,144p' .github/workflows/build.yaml
```

Expected output (last 8 lines of the file):
```
      - name: Publish Git tag + GitHub Release
        if: steps.semrel-dry.outputs.version != ''
        # go-semantic-release/action v1.24.1
        uses: go-semantic-release/action@2e9dc4247a6004f8377781bef4cb9dad273a741f
        with:
          bin: /tmp/semantic-release
          allow-initial-development-versions: true
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

If the output differs, the anchor changed — update Step 2's old/new strings accordingly.

- [ ] **Step 2: Append the three new steps**

Use the `Edit` tool on `.github/workflows/build.yaml`.

OLD STRING (the entire current "Publish Git tag + GitHub Release" step, used as anchor; leave it intact, just add new steps after it):

```
      - name: Publish Git tag + GitHub Release
        if: steps.semrel-dry.outputs.version != ''
        # go-semantic-release/action v1.24.1
        uses: go-semantic-release/action@2e9dc4247a6004f8377781bef4cb9dad273a741f
        with:
          bin: /tmp/semantic-release
          allow-initial-development-versions: true
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

NEW STRING (the same step, plus three appended steps, all 6-space-indented to match the existing `steps:` list):

```
      - name: Publish Git tag + GitHub Release
        if: steps.semrel-dry.outputs.version != ''
        # go-semantic-release/action v1.24.1
        uses: go-semantic-release/action@2e9dc4247a6004f8377781bef4cb9dad273a741f
        with:
          bin: /tmp/semantic-release
          allow-initial-development-versions: true
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Set up Go
        if: steps.semrel-dry.outputs.version != ''
        uses: actions/setup-go@v6
        with:
          go-version-file: go.mod

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

Make sure the trailing newline at the end of file is preserved (no double newline).

- [ ] **Step 3: Validate yaml syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/build.yaml'))"
```

Expected: no output, exit code 0.

- [ ] **Step 4: Validate the new steps are present and guarded**

Run:
```bash
grep -c "if: steps.semrel-dry.outputs.version != ''" .github/workflows/build.yaml
```

Expected: `8` (5 existing guards + 3 new ones — 8 total).

Run:
```bash
grep -E "Set up Go|Compile binaries and checksums|Upload binaries to GitHub Release" .github/workflows/build.yaml | wc -l
```

Expected: `3`.

If either count differs, re-check the Edit step — guards or step names are wrong.

- [ ] **Step 5: actionlint (if installed)**

Run:
```bash
command -v actionlint >/dev/null && actionlint .github/workflows/build.yaml || echo "actionlint not installed, skipping"
```

If actionlint reports errors, fix them. Common issue: indentation of the new steps (must be exactly 6 spaces for the `- name:` line).

- [ ] **Step 6: Commit**

Run:
```bash
git add .github/workflows/build.yaml
git commit -m "feat(ci): attach Go binaries to GitHub Releases"
```

If pre-commit hooks rewrite trailing whitespace and the commit fails, re-add and re-commit.

- [ ] **Step 7: Verify the commit landed on the branch**

Run:
```bash
git log --oneline -1
git diff HEAD~1 --stat -- .github/workflows/build.yaml
```

Expected:
- Top commit message starts with `feat(ci): attach Go binaries to GitHub Releases`.
- Diff stat shows ~30-35 insertions and 0 deletions on `.github/workflows/build.yaml`.

---

## Task 3: Push, open PR, merge, verify live release

**Why this task is here:** the workflow only runs on push to `main`, so we can't observe the new behavior until merge. The PR's CI runs `test`/`lint` only (no release attempt), validating the yaml syntactically and ensuring the existing tests still pass.

**Files:** none locally — all state changes are remote.

- [ ] **Step 1: Push the branch**

Run:
```bash
git push -u origin feat/release-binaries
```

Expected: branch pushed, tracking set up.

- [ ] **Step 2: Open the PR**

Run:
```bash
gh pr create --title "feat(ci): attach Go binaries to GitHub Releases" --body "$(cat <<'EOF'
## Summary

Implements [docs/superpowers/specs/2026-05-08-release-binaries-design.md](docs/superpowers/specs/2026-05-08-release-binaries-design.md).

Three new steps in the `release` job of `build.yaml`:

- `Set up Go` — `actions/setup-go@v6` (matches `test`/`lint` toolchain).
- `Compile binaries and checksums` — `go build` for both analyzers, `linux/amd64`, `-trimpath -ldflags="-s -w"`, plus a `.sha256` sidecar per binary.
- `Upload binaries to GitHub Release` — `gh release upload v$VERSION ... --clobber`.

All three steps guarded by the existing `if: steps.semrel-dry.outputs.version != ''`, so non-release commits skip them.

## Behavior change

Each release commit's GitHub Release now carries 4 supplementary asset files in addition to the existing GHCR images:

- `k8s-analyzer-v<version>-linux-amd64`
- `k8s-analyzer-v<version>-linux-amd64.sha256`
- `checkmk-analyzer-v<version>-linux-amd64`
- `checkmk-analyzer-v<version>-linux-amd64.sha256`

GHCR images remain the canonical deliverable; binaries are best-effort supplementary.

## Test plan

- [ ] CI green on this PR (`test` + `lint` only — release job runs only on `main`).
- [ ] After merge: first release run on `main` succeeds end-to-end, attaches all 4 assets to the new release.
- [ ] `sha256sum -c <file>.sha256` succeeds against the corresponding binary.
- [ ] Subsequent non-release commit on a build-relevant path: `test`+`lint` only, no release, no asset upload.
EOF
)"
```

Expected: PR URL printed.

- [ ] **Step 3: Wait for PR CI to pass**

Run:
```bash
gh pr checks --watch
```

Expected: `test` and `lint` jobs both green. Release job does **not** run on a feature branch (workflow `on: push: branches: [main]`).

If `test` or `lint` fail, check the log; the new yaml might have broken syntax that python's loose loader missed but Actions caught.

- [ ] **Step 4: Merge the PR**

Confirm with the user before merging if reviewing manually. Then:

```bash
gh pr merge --squash
```

Expected: PR merged, branch deleted on origin.

- [ ] **Step 5: Watch the live release run on main**

Run:
```bash
gh run list --branch main --limit 1
RUN_ID=$(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$RUN_ID" --exit-status
```

Expected: workflow completes successfully (~10-15 min total). The squash-merge commit is `feat(ci):`, so semantic-release will compute a minor bump and attempt to publish. The new asset upload step runs at the end.

If the run fails:
- At `Compile binaries and checksums`: read the log; likely a `go.mod` toolchain or path issue. The same source compiled minutes earlier in `test`/`lint`, so this is rare.
- At `Upload binaries to GitHub Release`: the release was created, assets weren't. Fix manually with `gh release upload v<version> <files...> --clobber` from the local checkout after pulling main.

- [ ] **Step 6: Verify the release page**

Run:
```bash
LATEST_TAG=$(gh release view --json tagName --jq .tagName)
echo "Latest release: $LATEST_TAG"
gh release view "$LATEST_TAG" --json assets --jq '.assets[] | {name, size}'
```

Expected: 4 asset entries, names matching the pattern `<component>-v<version>-linux-amd64` and `<component>-v<version>-linux-amd64.sha256`. Binary sizes ~10-25 MB; `.sha256` files ~100 bytes.

- [ ] **Step 7: Download an asset and verify the checksum**

Run (substitute `$LATEST_TAG` from Step 6):
```bash
mkdir -p /tmp/release-verify && cd /tmp/release-verify
gh release download "$LATEST_TAG" --pattern "k8s-analyzer-${LATEST_TAG}-linux-amd64" --pattern "k8s-analyzer-${LATEST_TAG}-linux-amd64.sha256"
sha256sum -c "k8s-analyzer-${LATEST_TAG}-linux-amd64.sha256"
```

Expected: `k8s-analyzer-vX.Y.Z-linux-amd64: OK`. If `FAILED`, the upload corrupted the binary or the sidecar — investigate.

- [ ] **Step 8: Smoke-test the binary**

Run:
```bash
chmod +x "k8s-analyzer-${LATEST_TAG}-linux-amd64"
"./k8s-analyzer-${LATEST_TAG}-linux-amd64" --help 2>&1 | head -20 || \
  "./k8s-analyzer-${LATEST_TAG}-linux-amd64" 2>&1 | head -5
```

Expected: either `--help` output OR a startup-time error like "missing WEBHOOK_SECRET" (the analyzer needs env vars to start). The point is the binary is a valid linux/amd64 executable that runs and exits cleanly. A `cannot execute binary file` error means the upload corrupted bytes.

Repeat Steps 7-8 for `checkmk-analyzer` if desired.

- [ ] **Step 9: Verify a subsequent non-release commit doesn't upload assets**

After the next push to main that has a non-release commit type (e.g. `chore: tidy logging`), watch the run:

```bash
gh run list --branch main --limit 2
gh run view <run_id> --json jobs --jq '.jobs[] | {name, conclusion}'
```

Expected: `test` + `lint` succeed. The `release` job runs but most of its steps are skipped (gated by `if: steps.semrel-dry.outputs.version != ''`). No new release, no new assets.

If the new asset-related steps run when they shouldn't, the `if:` guards are missing or wrong — check the log for which steps actually executed.

---

## Self-Review

1. **Spec coverage:** Goal/non-goals → Task 2; workflow architecture (3 new steps) → Task 2; permissions (no change) → no task needed; atomicity & failure modes → covered by Task 3 Step 5's failure-mode notes; rollback interaction → no task needed (passive doc); edge cases → Task 3 Step 9 (non-release commit verification); operator examples → Task 3 Steps 7-8.
2. **Placeholder scan:** no TBD/TODO/"implement later". The PR-body uses Markdown bullets that the engineer can adjust.
3. **Type/name consistency:** `outputs.version` referenced consistently. Filenames follow `<component>-v<version>-linux-amd64` exactly across compile, sha-sidecar, upload, and verify steps. Step IDs are stable (`semrel-dry` referenced unchanged from existing workflow).
4. **Granularity:** Tasks 1 and 2 are mechanical (8 steps total). Task 3 is the live-rollout phase (9 steps), longer because it intersects with GitHub-side state changes that can't be batched.

---

## Notes for the Implementing Engineer

- The Dockerfile is **not** modified by this plan. The Dockerfile-vs-release-asset binary divergence is intentional per the spec.
- If `gh` isn't installed locally for Task 3 verification (Step 7), use `curl -fsSL -O <release-asset-url>` instead. The asset URL is `https://github.com/<owner>/<repo>/releases/download/v<version>/<filename>`.
- If a release is published without binaries (upload step failed), recover with `gh release upload v<version> <files...> --clobber` after pulling main and rebuilding locally with the same flags from Task 2 Step 2.
- Runtime env vars are unrelated to this PR; binaries built here behave identically to the current Docker images at runtime.
