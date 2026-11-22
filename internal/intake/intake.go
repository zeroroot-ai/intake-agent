// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package intake reads the connectors of a tenant and hands each result to the
// daemon.
//
// The agent holds no vendor credential. The daemon is the one caller of a
// connector. The agent only asks the daemon to call a tool, and it hands each
// result back as a flaw or an alert.
//
// A pass reads each enabled connector that has a recipe. It skips a result that
// is behind the marker of the connector. After each result that the daemon
// accepted, it moves the marker. A restart then reads no result twice and skips
// none.
//
// An Alert has the identity of its connector and its result id, so a second
// read of one alert changes the same Alert. A finding has the identity that
// the daemon gives it. See the RaiseFlaw method of the daemon package for when
// that identity is stable.
package intake

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/zeroroot-ai/intake-agent/internal/recipe"
)

// ErrGrant means that the daemon refused the grant of the agent, for example
// because it expired. No later call can pass with that grant, so Run stops.
var ErrGrant = errors.New("intake: the daemon refused the grant")

// MaxItems is the largest number of results that one call hands to the daemon.
// A pass sorts the results by cursor and hands over the oldest MaxItems. The
// marker stops at the last one, so the next pass reads the rest.
const MaxItems = 1000

// Tool is one tool of one enabled connector, as the daemon lists it.
type Tool struct {
	Connector string
	Name      string
}

// Call is the outcome of one tool call.
type Call struct {
	// JSON is the result of the tool.
	JSON []byte
	// ID is the id that the daemon recorded for the call. It is the evidence
	// of the finding that the call raised.
	ID string
}

// Handoff is one result that the agent gives to the daemon.
type Handoff struct {
	Connector string
	Tool      string
	Class     recipe.Class
	// CallID is the recorded call that returned the result.
	CallID string
	Item   recipe.Item
}

// Caller lists and calls the tools of the enabled connectors. The daemon is the
// one caller of a connector, so each loop of the agent reaches a connector only
// through a Caller.
type Caller interface {
	// Tools lists the tools of the enabled connectors of the tenant.
	Tools(ctx context.Context) ([]Tool, error)
	// Invoke calls one tool of one connector.
	Invoke(ctx context.Context, connector, tool string, args map[string]any) (Call, error)
}

// Daemon is everything the agent needs from the harness.
type Daemon interface {
	Caller
	// RaiseFlaw hands over a flaw. The daemon makes it a finding.
	RaiseFlaw(ctx context.Context, h Handoff) error
	// RaiseAlert hands over an alert. The daemon makes it an Alert node.
	RaiseAlert(ctx context.Context, h Handoff) error
}

// Markers keeps the marker of each connector across restarts.
type Markers interface {
	Load(ctx context.Context) (map[string]recipe.Marker, error)
	Save(ctx context.Context, connector string, m recipe.Marker) error
}

// Summary is what one pass did.
type Summary struct {
	Connectors int
	// NoRecipe lists the connectors that the agent skipped, with no recipe.
	NoRecipe []string
	// NoTool lists the connectors whose server lacks the tool of the recipe.
	NoTool  []string
	Flaws   int
	Alerts  int
	Skipped int
	// Invalid counts the results with no id or no cursor. The pass skips them.
	Invalid int
	// Overflow counts the results over MaxItems in one call. The next pass
	// reads them.
	Overflow int
	// Failed lists the connectors that stopped with an error.
	Failed []string
}

// Reader runs the passes.
type Reader struct {
	daemon  Daemon
	markers Markers
	book    *recipe.Book
	log     *slog.Logger
}

// New builds a reader.
func New(d Daemon, m Markers, b *recipe.Book, log *slog.Logger) (*Reader, error) {
	if d == nil || m == nil || b == nil {
		return nil, errors.New("intake: a daemon, a marker store and a recipe book are required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Reader{daemon: d, markers: m, book: b, log: log}, nil
}

// Pass reads each enabled connector once.
//
// A failure in one connector does not stop the others. The error that Pass
// returns joins the failures, and the summary names the connectors.
func (r *Reader) Pass(ctx context.Context) (Summary, error) {
	var sum Summary
	tools, err := r.daemon.Tools(ctx)
	if err != nil {
		return sum, fmt.Errorf("list the connector tools: %w", err)
	}
	markers, err := r.markers.Load(ctx)
	if err != nil {
		return sum, fmt.Errorf("load the markers: %w", err)
	}
	byConnector := map[string]map[string]bool{}
	for _, t := range tools {
		if byConnector[t.Connector] == nil {
			byConnector[t.Connector] = map[string]bool{}
		}
		byConnector[t.Connector][t.Name] = true
	}
	names := make([]string, 0, len(byConnector))
	for c := range byConnector {
		names = append(names, c)
	}
	sort.Strings(names)
	sum.Connectors = len(names)

	var errs []error
	for _, name := range names {
		rec, ok := r.book.For(name)
		if !ok {
			sum.NoRecipe = append(sum.NoRecipe, name)
			continue
		}
		if !byConnector[name][rec.Tool] {
			sum.NoTool = append(sum.NoTool, name)
			continue
		}
		if err := r.readOne(ctx, rec, markers[name], &sum); err != nil {
			sum.Failed = append(sum.Failed, name)
			errs = append(errs, fmt.Errorf("connector %s: %w", name, err))
		}
	}
	return sum, errors.Join(errs...)
}

// readOne reads one connector and moves its marker after each accepted item.
func (r *Reader) readOne(ctx context.Context, rec recipe.Recipe, m recipe.Marker, sum *Summary) error {
	call, err := r.daemon.Invoke(ctx, rec.Connector, rec.Tool, rec.Args(m))
	if err != nil {
		return fmt.Errorf("call %s: %w", rec.Tool, err)
	}
	items, err := rec.Parse(call.JSON)
	if err != nil {
		return fmt.Errorf("read the result of %s: %w", rec.Tool, err)
	}
	todo := make([]recipe.Item, 0, len(items))
	for i, it := range items {
		switch {
		case it.ID == "" || it.Cursor == "":
			sum.Invalid++
			r.log.Warn("intake: skip a result with no id or no cursor",
				"connector", rec.Connector, "tool", rec.Tool, "index", i)
		case behind(m, it):
			sum.Skipped++
		default:
			todo = append(todo, it)
		}
	}
	sort.SliceStable(todo, func(i, j int) bool { return todo[i].Cursor < todo[j].Cursor })
	if len(todo) > MaxItems {
		sum.Overflow += len(todo) - MaxItems
		todo = todo[:MaxItems]
	}

	for _, it := range todo {
		h := Handoff{Connector: rec.Connector, Tool: rec.Tool, Class: rec.Class, CallID: call.ID, Item: it}
		if rec.Class.IsFlaw() {
			err = r.daemon.RaiseFlaw(ctx, h)
		} else {
			err = r.daemon.RaiseAlert(ctx, h)
		}
		if err != nil {
			return fmt.Errorf("hand over result %s: %w", it.ID, err)
		}
		if rec.Class.IsFlaw() {
			sum.Flaws++
		} else {
			sum.Alerts++
		}
		m = advance(m, it)
		if err := r.markers.Save(ctx, rec.Connector, m); err != nil {
			return fmt.Errorf("save the marker after result %s: %w", it.ID, err)
		}
	}
	return nil
}

// behind reports whether the marker already covers the item.
func behind(m recipe.Marker, it recipe.Item) bool {
	switch {
	case m.Cursor == "" || it.Cursor > m.Cursor:
		return false
	case it.Cursor < m.Cursor:
		return true
	}
	for _, id := range m.AtCursor {
		if id == it.ID {
			return true
		}
	}
	return false
}

// advance moves the marker over one item that the daemon accepted.
func advance(m recipe.Marker, it recipe.Item) recipe.Marker {
	if it.Cursor > m.Cursor {
		return recipe.Marker{Cursor: it.Cursor, AtCursor: []string{it.ID}}
	}
	at := make([]string, len(m.AtCursor), len(m.AtCursor)+1)
	copy(at, m.AtCursor)
	return recipe.Marker{Cursor: m.Cursor, AtCursor: append(at, it.ID)}
}

// Run reads every interval until the context ends. A failed pass is logged and
// the loop goes on, because an always-on agent must outlive a vendor outage.
// When the daemon refuses the grant (ErrGrant), Run returns the error, because
// no later pass can pass with that grant.
func (r *Reader) Run(ctx context.Context, interval time.Duration) error {
	return Loop(ctx, interval, r.log, "intake", func(ctx context.Context) error {
		sum, err := r.Pass(ctx)
		r.log.Info("intake pass done", "failed", sum.Failed, "connectors", sum.Connectors,
			"flaws", sum.Flaws, "alerts", sum.Alerts, "skipped", sum.Skipped, "invalid", sum.Invalid, "overflow", sum.Overflow,
			"no_recipe", sum.NoRecipe, "no_tool", sum.NoTool)
		return err
	})
}

// Loop runs pass now and then every interval, until the context ends. It is the
// one loop of the agent: the intake reader, the ticket mirror and the pager all
// use it. A pass that fails is logged and the loop goes on. A pass that returns
// ErrGrant stops the loop with that error, because no later pass can pass with
// the grant that the daemon refused.
func Loop(ctx context.Context, interval time.Duration, log *slog.Logger, name string,
	pass func(context.Context) error,
) error {
	if interval <= 0 {
		return fmt.Errorf("%s: the interval must be positive", name)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		err := pass(ctx)
		if errors.Is(err, ErrGrant) {
			return fmt.Errorf("%s pass: %w", name, err)
		}
		if err != nil {
			log.Error(name+" pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
