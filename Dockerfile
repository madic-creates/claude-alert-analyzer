# syntax=docker/dockerfile:1.25

# Tiny stage that only fetches kubectl. No Go toolchain — Go binaries are
# expected to already be built and present in the build context as
# `./k8s-analyzer` and `./checkmk-analyzer` (linux/amd64, CGO_ENABLED=0).
FROM alpine:3.24 AS kubectl-fetcher
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
FROM alpine:3.24 AS checkmk-analyzer
RUN apk add --no-cache ca-certificates openssh-client && rm -rf /var/cache/apk/*
COPY checkmk-analyzer /checkmk-analyzer
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/checkmk-analyzer"]
