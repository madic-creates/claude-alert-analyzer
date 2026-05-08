# CI Build Pipeline Speedup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce `Build Analyzer Images` workflow runtime from ~5 minutes to <2 minutes by compiling Go binaries exactly once and reusing them for image builds and release uploads.

**Architecture:** Today the Go toolchain runs four times per pipeline (test, lint, k8s Docker build, checkmk Docker build) plus a fifth `go build` for the release-binary upload. We will (1) restructure `.github/workflows/build.yaml` so `test`, `lint`, and a new `build` job run in parallel and share `setup-go`'s native cache, (2) make the `build` job produce both binaries once and publish them as workflow artifacts, and (3) shrink `Dockerfile` to a thin runtime image that `COPY`s the prebuilt binaries, removing the Go toolchain from image builds entirely. Local `docker build` users get a tiny `Makefile` target so the new prerequisite (binaries-on-disk) is one command away.

**Tech Stack:** GitHub Actions, Go 1.26, Docker Buildx, `actions/upload-artifact@v4` / `actions/download-artifact@v4`, semantic-release, GHCR.

---

## File Structure

Files we will create or modify:

- **Modify** `.github/workflows/build.yaml` — split into `test`, `lint`, `build` (parallel) → `release` (depends on all three, downloads binary artifacts, builds/pushes thin images, publishes release, uploads binaries)
- **Modify** `Dockerfile` — drop the `golang:1.26-alpine` builder stage; replace with a tiny `kubectl-fetcher` stage and runtime stages that `COPY` prebuilt binaries from the build context
- **Modify** `.dockerignore` — keep excluding `.git/.github/docs/*.md`; explicitly allow the binary artifact filenames (no change needed if `*` not excluded, but verify)
- **Create** `Makefile` — `make binaries`, `make images` targets so local builds remain ergonomic
- **Modify** `CLAUDE.md` — update the "Build & Test" section to reflect the new local-build commands

No test files are added: this is CI infrastructure. Verification is done by observing pipeline duration on a real `main` push (instructions included).

---

## Task 1: Refactor Dockerfile to consume prebuilt binaries

**Files:**
- Modify: `Dockerfile` (full rewrite, ~37 lines → ~30 lines)

- [ ] **Step 1: Replace the Dockerfile contents**

Open `Dockerfile` and replace its entire contents with:

```dockerfile
# syntax=docker/dockerfile:1.7

# Tiny stage that only fetches kubectl. No Go toolchain — Go binaries are
# expected to already be built and present in the build context as
# `./k8s-analyzer` and `./checkmk-analyzer` (linux/amd64, CGO_ENABLED=0).
FROM alpine:3.23 AS kubectl-fetcher
RUN apk add --no-cache ca-certificates curl
ARG KUBECTL_VERSION=v1.36.0
ARG KUBECTL_SHA256=123d8c8844f46b1244c547fffb3c17180c0c26dac9890589fe7e67763298748e
RUN curl -fsSL -o /kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && echo "${KUBECTL_SHA256}  /kubectl" | sha256sum -c - \
    && chmod +x /kubectl

# K8s analyzer: scratch + kubectl static binary (no shell needed)
FROM scratch AS k8s-analyzer
COPY --from=kubectl-fetcher /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=kubectl-fetcher /kubectl /usr/local/bin/kubectl
COPY k8s-analyzer /k8s-analyzer
# kubectl writes its discovery cache to $HOME/.kube/cache. Provide a HOME the
# nobody user can write to. /tmp is conventionally tmpfs in k8s pods.
ENV HOME=/tmp
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/k8s-analyzer"]

# CheckMK analyzer: Alpine (needs openssh-client)
FROM alpine:3.23 AS checkmk-analyzer
RUN apk add --no-cache ca-certificates openssh-client && rm -rf /var/cache/apk/*
COPY checkmk-analyzer /checkmk-analyzer
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/checkmk-analyzer"]
```

What changed vs. before:
- Removed the `golang:1.26-alpine` builder stage entirely (no `go mod download`, no `go build`).
- The `kubectl` fetch moved from the old builder stage into a dedicated `kubectl-fetcher` stage. This keeps the K8s image's CA-cert source identical to before (we still copy `/etc/ssl/certs/ca-certificates.crt` from the alpine layer).
- `COPY k8s-analyzer /k8s-analyzer` and `COPY checkmk-analyzer /checkmk-analyzer` now read from the **build context** (the workflow's working directory), not from a previous stage.

- [ ] **Step 2: Verify Dockerfile syntactically with hadolint or buildx (no actual binary needed yet)**

Run:

```bash
docker buildx build --target k8s-analyzer --no-cache --check .
```

Expected: parse succeeds (it may complain that `k8s-analyzer` is missing from context — that's fine; we are only checking syntax). If `--check` is unavailable in the local Buildx version, fall back to:

```bash
docker buildx build --target k8s-analyzer --load --no-cache . 2>&1 | head -20
```

Expected: build starts, then fails at the `COPY k8s-analyzer` line because the binary isn't built yet. That is the desired state — confirms the Dockerfile parses and reaches the COPY.

- [ ] **Step 3: Commit**

```bash
git add Dockerfile
git commit -m "refactor(docker): drop builder stage, copy prebuilt binaries from context"
```

---

## Task 2: Add Makefile for local ergonomic builds

**Files:**
- Create: `Makefile`

- [ ] **Step 1: Create the Makefile**

Create `Makefile` with these contents (use real TAB characters for recipe lines — Make requires tabs, not spaces):

```makefile
.PHONY: binaries images k8s-image checkmk-image clean

GO        ?= go
GOFLAGS   ?= -trimpath -ldflags=-s\ -w
CGO       ?= 0
GOOS      ?= linux
GOARCH    ?= amd64

binaries: k8s-analyzer checkmk-analyzer

k8s-analyzer:
	CGO_ENABLED=$(CGO) GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GOFLAGS) -o k8s-analyzer ./cmd/k8s-analyzer/

checkmk-analyzer:
	CGO_ENABLED=$(CGO) GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GOFLAGS) -o checkmk-analyzer ./cmd/checkmk-analyzer/

images: binaries k8s-image checkmk-image

k8s-image:
	docker build --target k8s-analyzer -t k8s-analyzer:local .

checkmk-image:
	docker build --target checkmk-analyzer -t checkmk-analyzer:local .

clean:
	rm -f k8s-analyzer checkmk-analyzer
```

- [ ] **Step 2: Verify the Makefile builds both binaries**

Run:

```bash
make clean && make binaries
ls -la k8s-analyzer checkmk-analyzer
```

Expected: two executables in the repo root, ~15–25 MB each, both linux/amd64.

- [ ] **Step 3: Verify the Makefile builds both images using prebuilt binaries**

Run:

```bash
make images
docker images | grep -E '(k8s|checkmk)-analyzer:local'
```

Expected: two images listed, both built in seconds (no Go compilation inside Docker). The build context upload should include the binaries.

- [ ] **Step 4: Add the binary filenames to .gitignore**

Open `.gitignore` (create if it doesn't exist) and append:

```
# Local build outputs (also produced by CI for releases)
/k8s-analyzer
/checkmk-analyzer
```

- [ ] **Step 5: Clean up before committing**

```bash
make clean
```

- [ ] **Step 6: Commit**

```bash
git add Makefile .gitignore
git commit -m "build: add Makefile for local binary + image builds"
```

---

## Task 3: Restructure CI workflow into parallel jobs sharing artifacts

**Files:**
- Modify: `.github/workflows/build.yaml` (full rewrite of `jobs:` section)

The new job graph:

```
test  ─┐
lint  ─┤
build ─┴─→ release
```

`test`, `lint`, `build` run in parallel. `build` produces both binaries as a single uploaded artifact named `binaries`. `release` downloads them, runs semantic-release dry-run, builds and pushes both images via the thin Dockerfile (each Docker build now takes seconds because there is no Go toolchain involved), publishes the Git tag + GitHub Release, and uploads the same prebuilt binaries to the release.

- [ ] **Step 1: Replace the contents of `.github/workflows/build.yaml`**

Replace the file with:

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
      - "Makefile"
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

  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with:
          go-version-file: go.mod
      - name: Compile both binaries
        run: |
          set -euo pipefail
          CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
            -trimpath -ldflags="-s -w" \
            -o k8s-analyzer ./cmd/k8s-analyzer/
          CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
            -trimpath -ldflags="-s -w" \
            -o checkmk-analyzer ./cmd/checkmk-analyzer/
          ls -la k8s-analyzer checkmk-analyzer
      - name: Upload binaries
        uses: actions/upload-artifact@v4
        with:
          name: binaries
          path: |
            k8s-analyzer
            checkmk-analyzer
          retention-days: 1
          if-no-files-found: error

  release:
    needs: [test, lint, build]
    runs-on: ubuntu-latest
    permissions:
      contents: write
      packages: write
    concurrency:
      group: release-${{ github.ref }}
      cancel-in-progress: false
    steps:
      - name: Checkout (full history + tags)
        uses: actions/checkout@v6
        with:
          fetch-depth: 0
          fetch-tags: true

      - name: Download prebuilt binaries
        uses: actions/download-artifact@v4
        with:
          name: binaries
          path: .

      - name: Make binaries executable
        run: chmod +x k8s-analyzer checkmk-analyzer

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
          allow-initial-development-versions: true
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
          cache-from: type=gha,scope=alert-analyzer
          cache-to: type=gha,scope=alert-analyzer,mode=max

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
          cache-from: type=gha,scope=alert-analyzer
          cache-to: type=gha,scope=alert-analyzer,mode=max

      - name: Publish Git tag + GitHub Release
        if: steps.semrel-dry.outputs.version != ''
        # go-semantic-release/action v1.24.1
        uses: go-semantic-release/action@2e9dc4247a6004f8377781bef4cb9dad273a741f
        with:
          bin: /tmp/semantic-release
          allow-initial-development-versions: true
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Rename binaries + checksums for release
        if: steps.semrel-dry.outputs.version != ''
        env:
          VERSION: ${{ steps.semrel-dry.outputs.version }}
        run: |
          set -euo pipefail
          for COMPONENT in k8s-analyzer checkmk-analyzer; do
            OUT="${COMPONENT}-v${VERSION}-linux-amd64"
            mv "$COMPONENT" "$OUT"
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

Key changes vs. old workflow:
- New `build` job runs in parallel with `test` and `lint`. All three use `setup-go@v6`, which by default caches `~/go/pkg/mod` and `~/.cache/go-build` keyed on `go.sum`, so module download happens once across the three runners' cache hits.
- The `release` job downloads the artifact (no second `go build`) and reuses both binaries for image builds and release upload.
- Both image builds now share `cache-from/to: scope=alert-analyzer` (was `scope=k8s-analyzer` and `scope=checkmk-analyzer`). With the Go toolchain gone the cache mostly contains the kubectl-fetcher stage and small alpine layers, but a single shared scope still avoids any duplicate work between the two image builds.
- The `Compile binaries and checksums` step is replaced by `Rename binaries + checksums for release`: it renames the existing artifacts in place and computes sha256s. No second compile.
- Added `Makefile` to `paths:` so changes to it trigger the workflow.

- [ ] **Step 2: Lint the workflow file**

Run:

```bash
yamllint .github/workflows/build.yaml || true
# Optional: actionlint catches more GitHub-Actions-specific issues
which actionlint && actionlint .github/workflows/build.yaml || echo "actionlint not installed, skipping"
```

Expected: yamllint reports either no errors or only style nits. actionlint (if installed) reports no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/build.yaml
git commit -m "ci: parallelize test/lint/build, reuse prebuilt binaries via artifacts"
```

---

## Task 4: Update CLAUDE.md build instructions

**Files:**
- Modify: `CLAUDE.md` (Build & Test section, lines around 11–28)

- [ ] **Step 1: Update the Build & Test section**

In `CLAUDE.md`, locate the "Build & Test" section. Replace this block:

````markdown
```bash
# Build both binaries
CGO_ENABLED=0 go build -o k8s-analyzer ./cmd/k8s-analyzer/
CGO_ENABLED=0 go build -o checkmk-analyzer ./cmd/checkmk-analyzer/

# Run all tests
go test ./...

# Run tests for a specific package
go test ./internal/shared/
go test ./internal/checkmk/

# Docker multi-stage build (two targets)
docker build --target k8s-analyzer -t k8s-analyzer .
docker build --target checkmk-analyzer -t checkmk-analyzer .
```
````

with:

````markdown
```bash
# Build both binaries (or use `make binaries`)
make binaries

# Run all tests
go test ./...

# Run tests for a specific package
go test ./internal/shared/
go test ./internal/checkmk/

# Docker images: the Dockerfile expects prebuilt binaries in the build
# context, so build them first. `make images` does both steps.
make images
```

**Note:** The Dockerfile no longer compiles Go. Always run `make binaries`
(or the underlying `go build` commands) before `docker build`. CI does this
automatically in the `build` job and uses workflow artifacts to feed the
image-build step.
````

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document new make-based local build workflow"
```

---

## Task 5: End-to-end verification

This task is run by a human (not an agent) because it requires pushing to `main` and observing real CI run times.

- [ ] **Step 1: Trigger the workflow on a feature branch first via workflow_dispatch**

```bash
git push origin HEAD:ci-speedup-test
gh workflow run build.yaml --ref ci-speedup-test
gh run watch
```

Expected: all four jobs run successfully. `test`, `lint`, `build` complete in roughly equal time (≈45–90 s each). `release` job runs after them but skips publishing because semantic-release dry-run will not find releasable commits on a non-`main` branch (its outputs will be empty, the `if:` guards skip image push and release). The job still completes successfully.

- [ ] **Step 2: Confirm the build job uploaded the artifact**

```bash
gh run view --log | grep -E '(Upload binaries|Total size)' || true
```

Expected: an `Upload binaries` log section showing both `k8s-analyzer` and `checkmk-analyzer` were uploaded.

- [ ] **Step 3: Smoke-test the resulting binaries locally**

```bash
gh run download --name binaries --dir /tmp/ci-binaries
file /tmp/ci-binaries/*
chmod +x /tmp/ci-binaries/*
/tmp/ci-binaries/k8s-analyzer --help 2>&1 | head -5 || true
/tmp/ci-binaries/checkmk-analyzer --help 2>&1 | head -5 || true
```

Expected: both files report as `ELF 64-bit LSB executable, x86-64, statically linked`. Running them prints either a help/usage message or a config error (acceptable — they require env vars to start).

- [ ] **Step 4: Merge to main and time the real release run**

After review, merge the branch to `main`:

```bash
gh pr create --title "ci: speed up build pipeline" --body "Implements docs/superpowers/plans/2026-05-08-ci-build-speedup.md"
# (review, approve)
gh pr merge --squash
gh run watch
```

Expected total wall-clock time: <2 min from push to release publish. The two image-build steps in `release` should each take ~10–20 s (down from 60–90 s) because no Go compilation happens inside Docker.

- [ ] **Step 5: Compare durations**

```bash
# List the last few build.yaml runs with their durations
gh run list --workflow=build.yaml --limit 5 \
  --json databaseId,createdAt,updatedAt,conclusion,displayTitle \
  --jq '.[] | "\(.displayTitle | .[0:50]) — \(.conclusion) — \(.createdAt) → \(.updatedAt)"'
```

Expected: the new run is at least 2× faster than the previous main runs from before the change.

If the new run is **not** faster:
- Check whether `setup-go@v6`'s cache hit on the second main run (first run after the change will have a cold cache; second run will show the steady-state speed). Re-trigger the workflow with `gh workflow run build.yaml` and compare.
- Check the `Build & push k8s-analyzer` and `Build & push checkmk-analyzer` step durations specifically — they should be <30 s each. If they are still slow, inspect the build log for unexpected Go activity.

---

## Self-Review Checklist

Spec coverage (against the original 4-point recommendation in the conversation):
- ✅ "Binaries einmal bauen, in Docker nur kopieren" — Tasks 1, 2, 3
- ✅ "test + lint + build parallelisieren statt sequentiell gaten" — Task 3
- ✅ "Docker-Buildx-Cache zusammenlegen" — Task 3 (single `scope=alert-analyzer`)
- ⚠️ "Race-Tests evtl. nicht im Hot-Path" — intentionally **not** included; this is a policy decision for the user, not a mechanical speedup. If the user wants it later, it's a one-line change to split `go test` into `go test -count=1 ./...` (fast, every push) + `go test -race -count=1 ./...` (scheduled / weekly).

Placeholder scan: no TBDs, no "implement later", every code block contains complete content, every command shows expected output.

Type/name consistency:
- Artifact name `binaries` is referenced consistently in upload (Task 3) and download (Task 3).
- Make targets `binaries`, `images`, `k8s-image`, `checkmk-image`, `clean` are defined in Task 2 and only referenced (not redefined) in Task 4.
- File paths `k8s-analyzer` and `checkmk-analyzer` (binary names) match across Dockerfile (Task 1), Makefile (Task 2), workflow (Task 3), and CLAUDE.md (Task 4).
