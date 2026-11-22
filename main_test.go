// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroroot-ai/intake-agent/internal/daemon"
	"github.com/zeroroot-ai/intake-agent/internal/intake"
	"github.com/zeroroot-ai/intake-agent/internal/mirror"
	"github.com/zeroroot-ai/intake-agent/internal/pager"
	"github.com/zeroroot-ai/intake-agent/internal/recipe"
)

// TestRunRefusesALaunchWithNoContract: the agent must fail at start and not dial
// with no grant.
func TestRunRefusesALaunchWithNoContract(t *testing.T) {
	for _, k := range []string{"GIBSON_CG_JWT", "GIBSON_CALLBACK_ENDPOINT", "GIBSON_INSTANCE_MODE"} {
		t.Setenv(k, "")
	}
	err := run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "launch contract") {
		t.Fatalf("err = %v", err)
	}
}

// TestNewLoopsNamesEachMissingPart: when no loop can start, one error reports
// every missing part.
func TestNewLoopsNamesEachMissingPart(t *testing.T) {
	_, err := newLoops(nil, shippedParts(), daemonSeams(nil), quiet())
	for _, want := range []error{
		recipe.ErrNoRecipes, daemon.ErrNoMarkerStore, daemon.ErrNoItemSource, daemon.ErrNoWaitSource,
	} {
		if !errors.Is(err, want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

type nilDaemon struct{}

func (nilDaemon) Tools(context.Context) ([]intake.Tool, error) { return nil, nil }
func (nilDaemon) Invoke(context.Context, string, string, map[string]any) (intake.Call, error) {
	return intake.Call{}, nil
}
func (nilDaemon) RaiseFlaw(context.Context, intake.Handoff) error  { return nil }
func (nilDaemon) RaiseAlert(context.Context, intake.Handoff) error { return nil }

type nilMarkers struct{}

func (nilMarkers) Load(context.Context) (map[string]recipe.Marker, error) { return nil, nil }
func (nilMarkers) Save(context.Context, string, recipe.Marker) error      { return nil }

type nilSource struct{}

func (nilSource) Waiting(context.Context) ([]pager.Waiting, error) { return nil, nil }
func (nilSource) Limit(context.Context) (time.Duration, error)     { return 0, nil }

type nilAdapter struct{}

func (nilAdapter) Connector() string { return "pagerduty" }
func (nilAdapter) Paged(context.Context, intake.Caller, string) (bool, error) {
	return false, nil
}
func (nilAdapter) Page(context.Context, intake.Caller, pager.Waiting, string) error { return nil }

// TestAMissingPartDisablesOnlyItsOwnLoop: the pager has its parts, the intake
// reader and the mirror do not. The pager starts.
func TestAMissingPartDisablesOnlyItsOwnLoop(t *testing.T) {
	p := parts{bookErr: recipe.ErrNoRecipes, tickets: mirror.Adapters(""), pagers: []pager.Adapter{nilAdapter{}}}
	s := daemonSeams(nil)
	s.waits = func() (pager.Source, error) { return nilSource{}, nil }
	var logs bytes.Buffer
	loops, err := newLoops(nilDaemon{}, p, s, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil || len(loops) != 1 || loops[0].name != "pager" {
		t.Fatalf("loops %v, err %v", loops, err)
	}
	for _, name := range []string{"intake", "mirror"} {
		if n := strings.Count(logs.String(), "loop="+name); n != 1 {
			t.Errorf("the %s loop logged %d disable lines, want 1", name, n)
		}
	}
}

// TestTheIntakeReaderStartsWhenItsOwnPartsExist: the other two loops have no
// source.
func TestTheIntakeReaderStartsWhenItsOwnPartsExist(t *testing.T) {
	book, err := recipe.NewBook(recipe.Recipe{
		Connector: "c", Tool: "t", Class: recipe.Scanner, Source: "https://example.com/doc",
		Args:  func(recipe.Marker) map[string]any { return nil },
		Parse: func([]byte) ([]recipe.Item, error) { return nil, nil },
	})
	if err != nil {
		t.Fatalf("book: %v", err)
	}
	s := daemonSeams(nil)
	s.markers = func() (intake.Markers, error) { return nilMarkers{}, nil }
	p := parts{book: book, tickets: mirror.Adapters(""), pagers: pager.Adapters()}
	loops, err := newLoops(nilDaemon{}, p, s, quiet())
	if err != nil || len(loops) != 1 || loops[0].name != "intake" {
		t.Fatalf("loops %v, err %v", loops, err)
	}
}

// TestAGrantRefusalInOneLoopDoesNotStopTheOthers: loop a stops at once with
// ErrGrant, and loop b still runs to the end of its context.
func TestAGrantRefusalInOneLoopDoesNotStopTheOthers(t *testing.T) {
	var after atomic.Int32
	loops := []loop{
		{"a", func(context.Context, time.Duration) error { return intake.ErrGrant }},
		{"b", func(ctx context.Context, _ time.Duration) error {
			time.Sleep(50 * time.Millisecond) // a ends long before this point
			after.Add(1)
			<-ctx.Done()
			return nil
		}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := runLoops(ctx, time.Second, loops, quiet())
	if !errors.Is(err, intake.ErrGrant) {
		t.Fatalf("err = %v, want the error of loop a", err)
	}
	if after.Load() != 1 {
		t.Fatal("loop b did not run to the end of its context")
	}
}

type nilItems struct{}

func (nilItems) Items(context.Context) ([]mirror.Item, error) { return nil, nil }

// TestEachLoopStartsWithItsShippedAdapterAndItsSource: the ticket adapters and the
// PagerDuty adapter ship, so a source is the only part that a loop still needs.
func TestEachLoopStartsWithItsShippedAdapterAndItsSource(t *testing.T) {
	book, err := recipe.NewBook(recipe.Recipe{
		Connector: "c", Tool: "t", Class: recipe.Scanner, Source: "https://example.com/doc",
		Args:  func(recipe.Marker) map[string]any { return nil },
		Parse: func([]byte) ([]recipe.Item, error) { return nil, nil },
	})
	if err != nil {
		t.Fatalf("book: %v", err)
	}
	s := seams{
		markers: func() (intake.Markers, error) { return nilMarkers{}, nil },
		items:   func() (mirror.Source, error) { return nilItems{}, nil },
		waits:   func() (pager.Source, error) { return nilSource{}, nil },
	}
	p := parts{book: book, tickets: mirror.Adapters(""), pagers: pager.Adapters()}
	loops, err := newLoops(nilDaemon{}, p, s, quiet())
	if err != nil || len(loops) != 3 {
		t.Fatalf("loops %v, err %v", loops, err)
	}
}
