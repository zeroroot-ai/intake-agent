// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command webhook-sender receives the webhook of a tool of the buyer and sends
// one A2A message to a published Gibson agent (gibson#1451).
//
// It runs next to the tool of the buyer, not inside Gibson. It is an enrolled
// identity with the ceiling mission:originate. See README.md, "The webhook
// sender".
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zeroroot-ai/intake-agent/internal/sender"
	"github.com/zeroroot-ai/sdk/a2ainbound"
	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

// Version is set at build time from the release tag. "dev" is a local build.
var Version = "dev"

// The environment of the sender.
const (
	envPlatformURL = "GIBSON_PLATFORM_URL"
	envHostKey     = "GIBSON_HOST_KEY_PATH"
	envAgent       = "SENDER_AGENT"
	envSource      = "SENDER_SOURCE"
	envSecret      = "SENDER_WEBHOOK_SECRET" //nolint:gosec // the name of a variable, not a secret
	envHeader      = "SENDER_SIGNATURE_HEADER"
	envListen      = "SENDER_LISTEN"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := run(ctx, os.Getenv); err != nil {
		slog.Error("webhook-sender", "version", Version, "err", err)
		stop()
		os.Exit(1)
	}
}

func run(ctx context.Context, getenv func(string) string) error {
	platform := getenv(envPlatformURL)
	if platform == "" {
		return fmt.Errorf("%s is not set", envPlatformURL)
	}
	// The first start reads GIBSON_BOOTSTRAP_TOKEN. A later start signs with the
	// host key on disk. When the enrollment fails, the sender does not listen,
	// so it never takes a webhook that it cannot send.
	//nolint:contextcheck // NewClient takes no context. It makes keys and contacts no server.
	identity, err := capabilitygrant.NewClient(capabilitygrant.ClientConfig{
		PlatformURL: platform, AgentName: "webhook-sender", HostKeyPath: getenv(envHostKey),
	})
	if err != nil {
		return fmt.Errorf("make the identity: %w", err)
	}
	defer func() { _ = identity.Close() }()
	if err := identity.Discover(ctx); err != nil {
		return fmt.Errorf("discover the platform: %w", err)
	}
	if err := identity.Register(ctx); err != nil {
		return fmt.Errorf("enroll the identity: %w", err)
	}
	client, err := a2ainbound.NewClient(a2ainbound.Config{BaseURL: platform, Signer: identity})
	if err != nil {
		return fmt.Errorf("make the A2A client: %w", err)
	}
	s, err := sender.New(client, sender.Config{
		Agent:           getenv(envAgent),
		Source:          getenv(envSource),
		Secret:          []byte(getenv(envSecret)),
		SignatureHeader: getenv(envHeader),
	}, slog.Default())
	if err != nil {
		return fmt.Errorf("sender: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", s.ServeHTTP)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	addr := getenv(envListen)
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	slog.Info("webhook-sender started", "version", Version, "listen", addr)
	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shut); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}
