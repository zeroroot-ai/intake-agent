// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

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
	// The write limit starts after the header. It covers the body read and the
	// send, so it is above the sum of the two.
	if srv.WriteTimeout <= srv.ReadTimeout+sender.DefaultSendTimeout {
		t.Fatalf("WriteTimeout %s does not cover the read %s and the send %s",
			srv.WriteTimeout, srv.ReadTimeout, sender.DefaultSendTimeout)
	}
	if shutdownTimeout < sender.DefaultSendTimeout {
		t.Fatalf("shutdownTimeout %s is below the send timeout", shutdownTimeout)
	}
}

// TestShutdownWaitsForARequestInFlight: a send that Gibson took must end.
func TestShutdownWaitsForARequestInFlight(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	srv := newServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusAccepted)
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	code := make(chan int, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String())
		if err != nil {
			code <- 0
			return
		}
		_ = resp.Body.Close()
		code <- resp.StatusCode
	}()
	<-started
	done := make(chan error, 1)
	go func() { done <- shutdown(context.Background(), srv) }()
	select {
	case <-done:
		t.Fatal("the shutdown did not wait for the request in flight")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if c := <-code; c != http.StatusAccepted {
		t.Fatalf("the request in flight got %d, want 202", c)
	}
}
