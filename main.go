// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command intake-agent is an always-on Gibson agent. It reads the security
// tools of the buyer through connectors. It turns each flaw into a finding and
// each alert into an Alert node. It also mirrors each finding and incident to
// the ticket tool of the buyer, and it pages a person for an item that waits too
// long.
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
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/zeroroot-ai/intake-agent/internal/daemon"
	"github.com/zeroroot-ai/intake-agent/internal/dispatch"
	"github.com/zeroroot-ai/intake-agent/internal/intake"
	"github.com/zeroroot-ai/intake-agent/internal/mirror"
	"github.com/zeroroot-ai/intake-agent/internal/pager"
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
	loops, err := newLoops(client, h, book)
	if err != nil {
		return err
	}
	return loops.run(ctx, m.Interval)
}

// loops are the three loops of the agent. They share one member, one grant and
// one callback client. See README.md for why they are not three agents.
type loops struct {
	reader *intake.Reader
	mirror *mirror.Mirror
	pager  *pager.Pager
}

// newLoops builds the loops. It reports each refusal, so that one start shows
// each missing part.
func newLoops(w daemon.Wire, h *daemon.Harness, book *recipe.Book) (*loops, error) {
	var errs []error
	fail := func(what string, err error) { errs = append(errs, fmt.Errorf("%s: %w", what, err)) }

	markers, err := daemon.NewMarkers(w)
	if err != nil {
		fail("markers", err)
	}
	items, err := daemon.NewItemSource(w)
	if err != nil {
		fail("mirror items", err)
	}
	tickets, err := mirror.Shipped()
	if err != nil {
		fail("mirror", err)
	}
	waits, err := daemon.NewWaitSource(w)
	if err != nil {
		fail("pager waits", err)
	}
	pagers, err := pager.Shipped()
	if err != nil {
		fail("pager", err)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	r, err := intake.New(h, markers, book, slog.Default())
	if err != nil {
		return nil, fmt.Errorf("reader: %w", err)
	}
	mi, err := mirror.New(h, items, tickets, slog.Default())
	if err != nil {
		return nil, fmt.Errorf("mirror: %w", err)
	}
	pg, err := pager.New(h, waits, pagers, slog.Default())
	if err != nil {
		return nil, fmt.Errorf("pager: %w", err)
	}
	return &loops{reader: r, mirror: mi, pager: pg}, nil
}

// run starts each loop. When one loop stops with an error, the others stop too.
func (l *loops) run(ctx context.Context, interval time.Duration) error {
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return l.reader.Run(ctx, interval) })
	g.Go(func() error { return l.mirror.Run(ctx, interval) })
	g.Go(func() error { return l.pager.Run(ctx, interval) })
	if err := g.Wait(); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
