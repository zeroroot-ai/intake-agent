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
	"sync"
	"syscall"
	"time"

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
	p := shippedParts()
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
	loops, err := newLoops(h, p, daemonSeams(client), slog.Default())
	if err != nil {
		return err
	}
	return runLoops(ctx, m.Interval, loops, slog.Default())
}

// envTicketQueue names the queue of the tickets: the project key on Jira, the id
// of the assignment group on ServiceNow. It is optional.
const envTicketQueue = "INTAKE_TICKET_QUEUE"

// parts are the static parts of the loops: what ships with the binary. An error
// means that the part is missing.
type parts struct {
	book    *recipe.Book
	bookErr error
	tickets []mirror.Adapter
	pagers  []pager.Adapter
}

func shippedParts() parts {
	var p parts
	p.book, p.bookErr = recipe.Default()
	p.tickets = mirror.Adapters(os.Getenv(envTicketQueue))
	p.pagers = pager.Adapters()
	return p
}

// seams are the parts of the loops that need the harness.
type seams struct {
	markers func() (intake.Markers, error)
	items   func() (mirror.Source, error)
	waits   func() (pager.Source, error)
}

func daemonSeams(w daemon.Wire) seams {
	return seams{
		markers: func() (intake.Markers, error) { return daemon.NewMarkers(w) },
		items:   func() (mirror.Source, error) { return daemon.NewItemSource(w) },
		waits:   func() (pager.Source, error) { return daemon.NewWaitSource(w) },
	}
}

// loop is one of the three loops of the agent. They share one member, one grant
// and one callback client. See README.md for why they are not three agents.
type loop struct {
	name string
	run  func(ctx context.Context, interval time.Duration) error
}

// newLoops builds each loop whose parts exist. A loop with a missing part is
// disabled and logs one line with each cause. The other loops start. When no
// loop can start, the error holds every cause.
func newLoops(d intake.Daemon, p parts, s seams, log *slog.Logger) ([]loop, error) {
	var loops []loop
	var all []error
	disabled := func(name string, errs ...error) {
		err := errors.Join(errs...)
		log.Warn("loop disabled: a part is missing", "loop", name, "err", err)
		all = append(all, fmt.Errorf("%s: %w", name, err))
	}

	markers, merr := s.markers()
	if err := errors.Join(wrap("recipes", p.bookErr), wrap("markers", merr)); err != nil {
		disabled("intake", err)
	} else if r, err := intake.New(d, markers, p.book, log); err != nil {
		disabled("intake", err)
	} else {
		loops = append(loops, loop{"intake", r.Run})
	}

	items, ierr := s.items()
	if err := wrap("items", ierr); err != nil {
		disabled("mirror", err)
	} else if mi, err := mirror.New(d, items, p.tickets, log); err != nil {
		disabled("mirror", err)
	} else {
		loops = append(loops, loop{"mirror", mi.Run})
	}

	waits, werr := s.waits()
	if err := wrap("waits", werr); err != nil {
		disabled("pager", err)
	} else if pg, err := pager.New(d, waits, p.pagers, log); err != nil {
		disabled("pager", err)
	} else {
		loops = append(loops, loop{"pager", pg.Run})
	}

	if len(loops) == 0 {
		return nil, fmt.Errorf("no loop can start: %w", errors.Join(all...))
	}
	return loops, nil
}

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", what, err)
}

// runLoops runs each loop on its own. A loop that stops with an error, for
// example with ErrGrant, does not stop the others. It returns when every loop
// has stopped, with the errors of the loops that failed.
func runLoops(ctx context.Context, interval time.Duration, loops []loop, log *slog.Logger) error {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for _, l := range loops {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.run(ctx, interval); err != nil {
				log.Error("loop stopped", "loop", l.name, "err", err)
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", l.name, err))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}
