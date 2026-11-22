// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package mirror copies each finding and each incident to the ticket tool of
// the buyer (gibson#1450).
//
// Gibson stays the source of truth. The mirror only writes to the ticket tool.
// A change in the ticket changes nothing in Gibson, and the mirror reads no
// field of a ticket to decide what a finding is.
//
// A pass reads the items, then reaches the ticket tool through an Adapter. The
// adapter calls the tools of one ticket connector through the daemon. The agent
// holds no vendor credential.
//
// The mirror keeps no state. For each item it asks the ticket tool if a ticket
// for that item exists. The ticket carries the item id and the last status that
// the mirror wrote. A restart so opens no second ticket.
package mirror

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/intake-agent/internal/intake"
)

// Kind is the kind of an item.
type Kind string

// The two kinds of item that the mirror copies.
const (
	KindFinding  Kind = "finding"
	KindIncident Kind = "incident"
)

// The last status of an item. A ticket closes when its item reaches it. The
// status of an incident is a name of the branch epic/incident-response. See
// README.md, "Open points".
const (
	statusVerified = "verified"
	statusResolved = "resolved"
)

// Item is a finding or an incident in Gibson.
type Item struct {
	Kind     Kind
	ID       string
	Title    string
	Severity string
	// Status is the status of the item in Gibson: open, fixing, fixed or
	// verified for a finding.
	Status string
	// URL is the link to the item in the console. It is in the ticket.
	URL string
}

// Done reports whether the item reached its last status.
func (i Item) Done() bool {
	switch i.Kind {
	case KindFinding:
		return i.Status == statusVerified
	case KindIncident:
		return i.Status == statusResolved
	}
	return false
}

// Source lists the items of the tenant. Gibson is the source.
type Source interface {
	Items(ctx context.Context) ([]Item, error)
}

// Ticket is one ticket of the ticket tool.
type Ticket struct {
	// Ref is the key of the ticket in the tool of the buyer.
	Ref string
	// Status is the status of the item at the last write of the mirror.
	Status string
	// Closed is true when the ticket is closed.
	Closed bool
}

// Adapter writes tickets in one ticket connector. It calls the tools of the
// connector through the Caller and reads each tool name, argument and result
// shape from a vendor document. README.md lists them.
type Adapter interface {
	// Connector is the catalog id of the ticket connector.
	Connector() string
	// Find returns the ticket of the item. The bool is false when none exists.
	Find(ctx context.Context, c intake.Caller, it Item) (Ticket, bool, error)
	// Open opens one ticket for the item, with its severity and its link.
	Open(ctx context.Context, c intake.Caller, it Item) (Ticket, error)
	// Update writes the new status of the item in the ticket.
	Update(ctx context.Context, c intake.Caller, t Ticket, it Item) error
	// Close closes the ticket.
	Close(ctx context.Context, c intake.Caller, t Ticket, it Item) error
}

// Adapters returns the adapters that ship with the agent. The list is empty on
// purpose: no vendor document that was read gives the arguments and the result
// of the ticket tools. README.md lists what is missing for each connector.
func Adapters() []Adapter { return nil }

// ErrNoAdapters is the refusal of Shipped.
var ErrNoAdapters = errors.New("mirror: no adapter ships, so the mirror has no ticket connector to write")

// Shipped returns the adapters that ship. It fails when none ships.
func Shipped() ([]Adapter, error) {
	a := Adapters()
	if len(a) == 0 {
		return nil, ErrNoAdapters
	}
	return a, nil
}

// Summary is what one pass did.
type Summary struct {
	Opened    int
	Updated   int
	Closed    int
	Unchanged int
	// NoTicket counts the done items that have no ticket. The mirror opens no
	// ticket for an item that is already done.
	NoTicket int
	// NoConnector is true when the tenant has no ticket connector.
	NoConnector bool
}

// Mirror runs the passes.
type Mirror struct {
	caller   intake.Caller
	src      Source
	adapters []Adapter
	log      *slog.Logger
	// warned is true after the mirror logged that the tenant has no ticket
	// connector. It is true until a connector appears.
	warned bool
}

// New builds a mirror.
func New(c intake.Caller, src Source, adapters []Adapter, log *slog.Logger) (*Mirror, error) {
	if c == nil || src == nil || len(adapters) == 0 {
		return nil, errors.New("mirror: a caller, a source and an adapter are required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Mirror{caller: c, src: src, adapters: adapters, log: log}, nil
}

// Pass mirrors each item once. A tenant with no ticket connector is not an
// error: the pass does nothing, and it logs this one time.
func (m *Mirror) Pass(ctx context.Context) (Summary, error) {
	var sum Summary
	tools, err := m.caller.Tools(ctx)
	if err != nil {
		return sum, fmt.Errorf("list the connector tools: %w", err)
	}
	a := m.pick(tools)
	if a == nil {
		sum.NoConnector = true
		if !m.warned {
			m.warned = true
			m.log.Info("mirror: the tenant has no ticket connector, so no ticket is written")
		}
		return sum, nil
	}
	m.warned = false
	items, err := m.src.Items(ctx)
	if err != nil {
		return sum, fmt.Errorf("read the items: %w", err)
	}
	var errs []error
	for _, it := range items {
		if err := m.one(ctx, a, it, &sum); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", it.Kind, it.ID, err))
		}
	}
	return sum, errors.Join(errs...)
}

// pick returns the first adapter whose connector is enabled.
func (m *Mirror) pick(tools []intake.Tool) Adapter {
	for _, a := range m.adapters {
		for _, t := range tools {
			if t.Connector == a.Connector() {
				return a
			}
		}
	}
	return nil
}

func (m *Mirror) one(ctx context.Context, a Adapter, it Item, sum *Summary) error {
	t, found, err := a.Find(ctx, m.caller, it)
	if err != nil {
		return fmt.Errorf("find the ticket: %w", err)
	}
	switch {
	case !found && it.Done():
		sum.NoTicket++
	case !found:
		m.log.Info("mirror: open a ticket", "kind", it.Kind, "id", it.ID, "title", it.Title,
			"severity", it.Severity, "link", it.URL)
		if _, err := a.Open(ctx, m.caller, it); err != nil {
			return fmt.Errorf("open the ticket: %w", err)
		}
		sum.Opened++
	case it.Done() && t.Closed, !it.Done() && t.Status == it.Status && !t.Closed:
		sum.Unchanged++
	case it.Done():
		if err := a.Close(ctx, m.caller, t, it); err != nil {
			return fmt.Errorf("close the ticket %s: %w", t.Ref, err)
		}
		sum.Closed++
	default:
		if err := a.Update(ctx, m.caller, t, it); err != nil {
			return fmt.Errorf("update the ticket %s: %w", t.Ref, err)
		}
		sum.Updated++
	}
	return nil
}

// Run mirrors every interval until the context ends.
func (m *Mirror) Run(ctx context.Context, interval time.Duration) error {
	return intake.Loop(ctx, interval, m.log, "mirror", func(ctx context.Context) error {
		sum, err := m.Pass(ctx)
		m.log.Info("mirror pass done", "opened", sum.Opened, "updated", sum.Updated, "closed", sum.Closed,
			"unchanged", sum.Unchanged, "no_ticket", sum.NoTicket, "no_connector", sum.NoConnector)
		return err
	})
}
