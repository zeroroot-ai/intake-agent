// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command intake-agent is an always-on Gibson agent. It reads the security
// tools of the buyer through connectors. It turns each flaw into a finding and
// each alert into an Alert node.
//
// It runs as a bank member (ADR-0119). It holds no vendor credential and has
// no egress. The daemon is the one caller of a connector.
//
// See AGENTS.md for the contract of this binary.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/zeroroot-ai/intake-agent/internal/daemon"
	"github.com/zeroroot-ai/intake-agent/internal/dispatch"
	"github.com/zeroroot-ai/intake-agent/internal/intake"
	"github.com/zeroroot-ai/intake-agent/internal/recipe"
	"github.com/zeroroot-ai/sdk/serve"
)

// AgentName is the name that the findings of this agent carry.
const AgentName = "intake-agent"

// Version is set at build time from the release tag. "dev" is a local build.
var Version = "dev"

func main() {
	os.Exit(exitCode())
}

// exitCode runs the agent and returns the exit status. It exists so that the
// signal context stops before the process exits.
func exitCode() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error(AgentName, "version", Version, "err", err)
		return 1
	}
	return 0
}

func run(ctx context.Context) error {
	m, err := dispatch.FromEnv()
	if err != nil {
		return fmt.Errorf("read the launch contract: %w", err)
	}
	// The recipe book comes before the dial. An agent with no recipe reads
	// nothing, so it refuses to start and never runs as an empty loop.
	book, err := recipe.Default()
	if err != nil {
		return fmt.Errorf("recipes: %w", err)
	}
	slog.Info("member started", "version", Version, "mission", m.MissionID,
		"mission_run", m.MissionRunID, "agent_run", m.AgentRunID, "interval", m.Interval.String())

	client, err := serve.NewCallbackClient(m.CallbackEndpoint, serve.WithCallbackToken(m.Grant))
	if err != nil {
		return fmt.Errorf("callback client: %w", err)
	}
	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("dial %s: %w", m.CallbackEndpoint, err)
	}
	defer func() {
		if cerr := client.Close(); cerr != nil && !errors.Is(cerr, context.Canceled) {
			slog.Warn("close callback client", "err", cerr)
		}
	}()
	client.SetFullContext(serve.TaskContextParams{
		AgentName: AgentName, MissionID: m.MissionID, MissionRunID: m.MissionRunID, AgentRunID: m.AgentRunID,
	})

	h, err := daemon.New(client, AgentName)
	if err != nil {
		return fmt.Errorf("harness: %w", err)
	}
	markers, err := daemon.NewMarkers(client)
	if err != nil {
		return fmt.Errorf("markers: %w", err)
	}
	reader, err := intake.New(h, markers, book, slog.Default())
	if err != nil {
		return fmt.Errorf("reader: %w", err)
	}
	if err := reader.Run(ctx, m.Interval); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
