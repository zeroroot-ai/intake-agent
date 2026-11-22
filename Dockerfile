# Stage 1: build — compiles the agent binary with CGO disabled.
FROM ghcr.io/zeroroot-ai/mirror/golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder

# The builder image carries exactly the Go that go.mod names, and the org
# guard (check-go-toolchain.sh, .github#22) fails a PR where they differ.
# GOTOOLCHAIN=local makes a mismatch fail the build instead of downloading a
# toolchain, so the pinned base is the toolchain that built the binary.
ARG GOTOOLCHAIN=local
ENV GOTOOLCHAIN=${GOTOOLCHAIN}

# VERSION is stamped into the binary so a running container reports the
# release it was built from. Without it every image reports "dev", which is
# indistinguishable from a local build in the console and in the registry.
ARG VERSION=dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION}" -o /out/intake-agent . \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION}" -o /out/webhook-sender ./cmd/webhook-sender

# Stage 2: runtime — distroless, non-root.
#
# static-debian13, not static-debian12. The binary is static and reads nothing
# from the Debian userland. The same base and digest as cve-triage. Move the
# digest here when a scanner names a package in this image.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS runtime

# The binary sits at a stable, documented path because setec does NOT consult
# the image ENTRYPOINT. The catalog manifest names the member command
# explicitly (`memberCommand: /intake-agent`). Moving this path breaks the
# launch, so it is part of the contract.
COPY --from=builder /out/intake-agent /intake-agent
# The webhook sender is a second binary of the same image (gibson#1451). The
# catalog runs it with its own command, never as a bank member.
COPY --from=builder /out/webhook-sender /webhook-sender

# No EXPOSE and no component.yaml: the agent is a bank member (ADR-0119). It
# serves no port and dials the harness callback service outbound only. The
# webhook sender listens on the address in SENDER_LISTEN.

# The license text travels with the distribution. Apache-2.0 §4(a) and MIT
# both require the notice to reach every recipient, and a published image is
# a distribution. /licenses is the OCI convention. COPY needs no shell, so it
# works on this distroless base. Last in the stage so a change here rebuilds
# nothing else.
COPY LICENSE /licenses/LICENSE

ENTRYPOINT ["/intake-agent"]
