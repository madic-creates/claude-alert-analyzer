FROM golang:1.26-alpine AS builder
RUN apk add --no-cache ca-certificates curl
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /k8s-analyzer ./cmd/k8s-analyzer/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /checkmk-analyzer ./cmd/checkmk-analyzer/

# Fetch kubectl statically. Pin version + sha256 for reproducibility.
ARG KUBECTL_VERSION=v1.36.0
ARG KUBECTL_SHA256=123d8c8844f46b1244c547fffb3c17180c0c26dac9890589fe7e67763298748e
RUN curl -fsSL -o /kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && echo "${KUBECTL_SHA256}  /kubectl" | sha256sum -c - \
    && chmod +x /kubectl

# K8s analyzer: scratch + kubectl static binary (no shell needed)
FROM scratch AS k8s-analyzer
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /k8s-analyzer /k8s-analyzer
COPY --from=builder /kubectl /usr/local/bin/kubectl
# kubectl writes its discovery cache to $HOME/.kube/cache. Provide a HOME the
# nobody user can write to. /tmp is conventionally tmpfs in k8s pods.
ENV HOME=/tmp
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/k8s-analyzer"]

# CheckMK analyzer: Alpine (needs openssh-client)
FROM alpine:3.23 AS checkmk-analyzer
RUN apk add --no-cache ca-certificates openssh-client && rm -rf /var/cache/apk/*
COPY --from=builder /checkmk-analyzer /checkmk-analyzer
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/checkmk-analyzer"]
