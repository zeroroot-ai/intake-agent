// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"strings"
	"testing"
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
		envPlatformURL: "https://127.0.0.1:1",
		envHostKey:     t.TempDir() + "/host_key.json",
		envListen:      "127.0.0.1:0",
	}
	err := run(context.Background(), func(k string) string { return env[k] })
	if err == nil || !strings.Contains(err.Error(), "discover the platform") {
		t.Fatalf("err = %v", err)
	}
}
