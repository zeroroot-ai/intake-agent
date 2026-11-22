// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package pager pages a person for an item that waits on a person
// (gibson#1501).
//
// Gibson lists the items that wait on a person, with the time that each one
// waited (ListWaitingOnPerson, gibson#1500). The tenant sets a wait limit. An
// item that waited longer than the limit gives one page to the person on call.
// The page goes out through the paging connector of the tenant, which is
// PagerDuty. The agent holds no vendor credential.
//
// One item gives one page. An item is one wait: the kind, the id and the time
// that the wait started. The pager keeps the pages that it sent in memory, and
// it also asks the paging tool before each page. A restart so sends no second
// page.
package pager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/zeroroot-ai/intake-agent/internal/intake"
)

// DefaultLimit is the wait limit of a tenant that set none (owner decision,
// 2026-11-21). A limit that the tenant sets replaces it.
const DefaultLimit = 4 * time.Hour

// Waiting is one item that waits on a person.
type Waiting struct {
	// Kind is destructive_action, merge_refused, next_scan or no_health_signal.
	Kind string
	// ID is the id of the finding, or of the hypothesis for a destructive
	// action.
	ID string
	// Since is the time that the wait started.
	Since time.Time
	// Waited is the time that the item has waited.
	Waited time.Duration
	// URL is the link to the item in the console. It is in the page.
	URL string
}

// Key names one wait. Two reads of the same wait give the same key. A new wait
// of the same item starts at another time, so it gives a new key and a new page.
func Key(w Waiting) string {
	return "wait:" + w.Kind + ":" + w.ID + ":" + strconv.FormatInt(w.Since.Unix(), 10)
}

// Source is Gibson. It lists the items that wait on a person, and it gives the
// wait limit that the tenant set. The limit is the only setting of the tenant.
type Source interface {
	Waiting(ctx context.Context) ([]Waiting, error)
	// Limit is the wait limit of the tenant. Zero means that the tenant set none,
	// and the pager then uses DefaultLimit.
	Limit(ctx context.Context) (time.Duration, error)
}

// Adapter sends a page through one paging connector. It calls the tools of the
// connector through the Caller. The tool names, the arguments and the results
// are those of the pagerduty server of zeroroot-ai/connectors.
type Adapter interface {
	// Connector is the catalog id of the paging connector.
	Connector() string
	// Paged reports whether the paging tool already holds a page with the key.
	Paged(ctx context.Context, c intake.Caller, key string) (bool, error)
	// Page pages the person on call. The page holds the key and the link of the
	// item, so that Paged can find it.
	Page(ctx context.Context, c intake.Caller, w Waiting, key string) error
}

// Adapters returns the adapters that ship: PagerDuty, through the paging server
// of zeroroot-ai/connectors.
func Adapters() []Adapter { return []Adapter{NewOnCall()} }

// Summary is what one pass did.
type Summary struct {
	Waiting int
	Paged   int
	// Already counts the waits that already have a page.
	Already int
	// NoConnector is true when the tenant has no paging connector.
	NoConnector bool
	// Limit is the wait limit of this pass: the tenant setting, or DefaultLimit.
	Limit time.Duration
}

// Pager runs the passes.
type Pager struct {
	caller   intake.Caller
	src      Source
	adapters []Adapter
	log      *slog.Logger
	// sent holds the key of each page that this process sent or found.
	sent map[string]bool
	// warnedNoConnector is true after the pager logged that the tenant has no
	// paging connector. It is true until a connector appears.
	warnedNoConnector bool
}

// New builds a pager.
func New(c intake.Caller, src Source, adapters []Adapter, log *slog.Logger) (*Pager, error) {
	if c == nil || src == nil || len(adapters) == 0 {
		return nil, errors.New("pager: a caller, a source and an adapter are required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Pager{caller: c, src: src, adapters: adapters, log: log, sent: map[string]bool{}}, nil
}

// Pass pages for each wait that is over the limit and has no page. A tenant
// with no paging connector is not an error: the pass does nothing, and it logs
// this one time. A tenant with no wait limit gets DefaultLimit.
func (p *Pager) Pass(ctx context.Context) (Summary, error) {
	var sum Summary
	tools, err := p.caller.Tools(ctx)
	if err != nil {
		return sum, fmt.Errorf("list the connector tools: %w", err)
	}
	a := p.pick(tools)
	if a == nil {
		sum.NoConnector = true
		if !p.warnedNoConnector {
			p.warnedNoConnector = true
			p.log.Info("pager: the tenant has no paging connector, so no page is sent")
		}
		return sum, nil
	}
	p.warnedNoConnector = false
	limit, err := p.src.Limit(ctx)
	if err != nil {
		return sum, fmt.Errorf("read the wait limit: %w", err)
	}
	if limit <= 0 {
		limit = DefaultLimit
	}
	sum.Limit = limit
	items, err := p.src.Waiting(ctx)
	if err != nil {
		return sum, fmt.Errorf("read the waiting items: %w", err)
	}
	sum.Waiting = len(items)

	live := make(map[string]bool, len(items))
	var errs []error
	for _, w := range items {
		key := Key(w)
		live[key] = true
		if w.Waited <= limit {
			continue
		}
		if err := p.one(ctx, a, w, key, &sum); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", w.Kind, w.ID, err))
		}
	}
	// A wait that ended needs no memory.
	for key := range p.sent {
		if !live[key] {
			delete(p.sent, key)
		}
	}
	return sum, errors.Join(errs...)
}

func (p *Pager) pick(tools []intake.Tool) Adapter {
	for _, a := range p.adapters {
		for _, t := range tools {
			if t.Connector == a.Connector() {
				return a
			}
		}
	}
	return nil
}

func (p *Pager) one(ctx context.Context, a Adapter, w Waiting, key string, sum *Summary) error {
	if p.sent[key] {
		sum.Already++
		return nil
	}
	held, err := a.Paged(ctx, p.caller, key)
	if err != nil {
		return fmt.Errorf("find the page: %w", err)
	}
	if held {
		p.sent[key] = true
		sum.Already++
		return nil
	}
	p.log.Info("pager: page the person on call", "kind", w.Kind, "id", w.ID, "waited", w.Waited, "link", w.URL)
	if err := a.Page(ctx, p.caller, w, key); err != nil {
		return fmt.Errorf("send the page: %w", err)
	}
	p.sent[key] = true
	sum.Paged++
	return nil
}

// Run pages every interval until the context ends.
func (p *Pager) Run(ctx context.Context, interval time.Duration) error {
	err := intake.Loop(ctx, interval, p.log, "pager", func(ctx context.Context) error {
		sum, err := p.Pass(ctx)
		p.log.Info("pager pass done", "waiting", sum.Waiting, "paged", sum.Paged, "already", sum.Already,
			"no_connector", sum.NoConnector, "limit", sum.Limit)
		return err
	})
	if err != nil {
		return fmt.Errorf("run the pager: %w", err)
	}
	return nil
}
