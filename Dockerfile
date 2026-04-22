FROM golang:1.26-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /k8s-analyzer ./cmd/k8s-analyzer/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /checkmk-analyzer ./cmd/checkmk-analyzer/

# K8s analyzer: scratch (no SSH needed)
FROM scratch AS k8s-analyzer
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /k8s-analyzer /k8s-analyzer
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
