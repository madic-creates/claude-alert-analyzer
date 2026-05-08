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
