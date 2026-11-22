// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroroot-ai/intake-agent/internal/sender"
)

func TestRunNeedsThePlatformURL(t *testing.T) {
	err := run(context.Background(), func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), envPlatformURL) {
		t.Fatalf("err = %v", err)
	}
}

// TestRunDoesNotListenWhenTheEnrollmentFails: a sender with no grant must not
// take a webhook. The platform here does not exist, so the enrollment fails.
func TestRunDoesNotListenWhenTheEnrollmentFails(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	env := map[string]string{
		envAgent: "incident-response", envSource: "edr", envSecret: strings.Repeat("s", 32),
		envPlatformURL: "https://127.0.0.1:1",
		envHostKey:     t.TempDir() + "/host_key.json",
		envListen:      "127.0.0.1:0",
	}
	err := run(context.Background(), func(k string) string { return env[k] })
	if err == nil || !strings.Contains(err.Error(), "discover the platform") {
		t.Fatalf("err = %v", err)
	}
}

// TestRunRefusesAShortSecretBeforeItEnrolls: the check comes before any network
// call, so the platform here is not even reachable.
func TestRunRefusesAShortSecretBeforeItEnrolls(t *testing.T) {
	env := map[string]string{
		envAgent: "incident-response", envSource: "edr", envSecret: strings.Repeat("s", 31),
		envPlatformURL: "https://127.0.0.1:1",
	}
	err := run(context.Background(), func(k string) string { return env[k] })
	if err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("err = %v", err)
	}
}

func TestTheServerHasEachTimeLimit(t *testing.T) {
	srv := newServer(":0", http.NewServeMux())
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("a time limit is not set: %+v", srv)
	}
	// A send to Gibson must end before the write limit.
	if srv.WriteTimeout <= sender.DefaultSendTimeout {
		t.Fatalf("WriteTimeout %s is not above the send timeout %s", srv.WriteTimeout, sender.DefaultSendTimeout)
	}
}
