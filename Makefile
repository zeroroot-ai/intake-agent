BINARY := intake-agent
# VERSION is stamped into the binary. Defaults to the nearest tag, so a local
# build reports what it actually is rather than a number someone typed.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.Version=$(VERSION)

# ast-checks ships the per-declaration read counter behind #33. Pinned, because
# a floating version would change the count without a commit.
UNWIRED_VERSION ?= v0.8.1

.PHONY: build test check check-fmt vet lint lint-unwired lint-unwired-write run image

## build: compile the agent binary and the webhook sender.
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) .
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o webhook-sender ./cmd/webhook-sender

## test: run unit tests.
test:
	go test ./...

## check: run the guards CI runs on a pull request. golangci-lint is not one
## of them: CI scopes it to new code with --new-from-rev, so `make lint` is a
## deliberately wider run and stays separate.
check: check-fmt vet lint-unwired

## check-fmt: fail when any file is not gofmt-clean.
check-fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

## vet: report suspicious constructs.
vet:
	go vet ./...

## lint: golangci-lint on the whole module (CI lints only new code).
lint:
	golangci-lint run ./...

## lint-unwired: fail if a declaration nothing reads is added (#33). The
## baseline only shrinks; a kept entry carries its reason on a # line.
lint-unwired:
	go run github.com/zeroroot-ai/ast-checks/cmd/unwired@$(UNWIRED_VERSION) -dir . -baseline .unwired-baseline.txt

## lint-unwired-write: re-measure #33 and rewrite the baseline.
lint-unwired-write:
	go run github.com/zeroroot-ai/ast-checks/cmd/unwired@$(UNWIRED_VERSION) -dir . -baseline .unwired-baseline.txt -write

## run: run the compiled binary once. Set the launch contract variables of
## README.md first; the binary reads its task from them and runs one pass.
run: build
	./$(BINARY)

## image: build the container image.
image:
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) .
