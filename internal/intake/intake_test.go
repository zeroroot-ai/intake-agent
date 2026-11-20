// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package intake

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/intake-agent/internal/recipe"
)

var errBoom = errors.New("boom")

type fakeDaemon struct {
	tools   []Tool
	results map[string]string // connector -> JSON
	invoked []string
	args    []map[string]any
	flaws   []Handoff
	alerts  []Handoff
	failOn  string // result id that RaiseFlaw/RaiseAlert refuses
}

func (f *fakeDaemon) Tools(context.Context) ([]Tool, error) { return f.tools, nil }

func (f *fakeDaemon) Invoke(_ context.Context, c, tool string, args map[string]any) (Call, error) {
	f.invoked = append(f.invoked, c+"/"+tool)
	f.args = append(f.args, args)
	if f.results[c] == "" {
		return Call{}, errBoom
	}
	return Call{JSON: []byte(f.results[c]), ID: "call-" + c}, nil
}

func (f *fakeDaemon) RaiseFlaw(_ context.Context, h Handoff) error {
	if h.Item.ID == f.failOn {
		return errBoom
	}
	f.flaws = append(f.flaws, h)
	return nil
}

func (f *fakeDaemon) RaiseAlert(_ context.Context, h Handoff) error {
	if h.Item.ID == f.failOn {
		return errBoom
	}
	f.alerts = append(f.alerts, h)
	return nil
}

type memMarkers struct {
	m     map[string]recipe.Marker
	saves int
}

func (s *memMarkers) Load(context.Context) (map[string]recipe.Marker, error) { return s.m, nil }

func (s *memMarkers) Save(_ context.Context, c string, m recipe.Marker) error {
	s.m[c] = m
	s.saves++
	return nil
}

// testRecipe reads a JSON array of {"id","at"} objects.
func testRecipe(connector string, class recipe.Class) recipe.Recipe {
	return recipe.Recipe{
		Connector: connector, Class: class, Source: "https://vendor.example/doc", Tool: "list",
		Args: func(m recipe.Marker) map[string]any { return map[string]any{"after": m.Cursor} },
		Parse: func(b []byte) ([]recipe.Item, error) {
			var rows []struct{ ID, At string }
			if err := json.Unmarshal(b, &rows); err != nil {
				return nil, fmt.Errorf("decode: %w", err)
			}
			out := make([]recipe.Item, len(rows))
			for i, r := range rows {
				out[i] = recipe.Item{ID: r.ID, Cursor: r.At, Title: "t " + r.ID}
			}
			return out, nil
		},
	}
}

func newReader(t *testing.T, d Daemon, m Markers, rs ...recipe.Recipe) *Reader {
	t.Helper()
	book, err := recipe.NewBook(rs...)
	if err != nil {
		t.Fatalf("book: %v", err)
	}
	r, err := New(d, m, book, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return r
}

func TestPassRoutesByClass(t *testing.T) {
	d := &fakeDaemon{
		tools: []Tool{{"scan", "list"}, {"edr", "list"}, {"idp", "list"}, {"cloud", "list"}, {"siem", "list"}},
		results: map[string]string{
			"scan":  `[{"ID":"1","At":"a"}]`,
			"edr":   `[{"ID":"2","At":"a"}]`,
			"idp":   `[{"ID":"3","At":"a"}]`,
			"cloud": `[{"ID":"4","At":"a"}]`,
			"siem":  `[{"ID":"5","At":"a"}]`,
		},
	}
	r := newReader(t, d, &memMarkers{m: map[string]recipe.Marker{}},
		testRecipe("scan", recipe.Scanner), testRecipe("edr", recipe.EDR), testRecipe("idp", recipe.Identity),
		testRecipe("cloud", recipe.Cloud), testRecipe("siem", recipe.SIEM))
	sum, err := r.Pass(context.Background())
	if err != nil {
		t.Fatalf("pass: %v", err)
	}
	if len(d.flaws) != 2 || len(d.alerts) != 3 || sum.Flaws != 2 || sum.Alerts != 3 {
		t.Fatalf("flaws=%d alerts=%d sum=%+v", len(d.flaws), len(d.alerts), sum)
	}
	for _, f := range d.flaws {
		if f.Class != recipe.Scanner && f.Class != recipe.Cloud {
			t.Errorf("a %s result became a finding", f.Class)
		}
		if f.CallID == "" {
			t.Error("a flaw must carry the recorded call id")
		}
	}
}

func TestPassSkipsWhatHasNoRecipeOrNoTool(t *testing.T) {
	d := &fakeDaemon{
		tools:   []Tool{{"known", "other"}, {"unknown", "list"}, {"known2", "list"}},
		results: map[string]string{"known2": `[]`},
	}
	r := newReader(t, d, &memMarkers{m: map[string]recipe.Marker{}},
		testRecipe("known", recipe.Scanner), testRecipe("known2", recipe.Scanner))
	sum, err := r.Pass(context.Background())
	if err != nil {
		t.Fatalf("pass: %v", err)
	}
	if len(sum.NoRecipe) != 1 || sum.NoRecipe[0] != "unknown" || len(sum.NoTool) != 1 || sum.NoTool[0] != "known" {
		t.Fatalf("summary = %+v", sum)
	}
	if len(d.invoked) != 1 || d.invoked[0] != "known2/list" {
		t.Fatalf("invoked = %v", d.invoked)
	}
}

// TestRestartReadsNoResultTwiceAndSkipsNone is the acceptance test of the
// marker: the second pass gives the same read, and only the new result moves.
func TestRestartReadsNoResultTwiceAndSkipsNone(t *testing.T) {
	d := &fakeDaemon{
		tools:   []Tool{{"scan", "list"}},
		results: map[string]string{"scan": `[{"ID":"b","At":"2"},{"ID":"a","At":"1"},{"ID":"c","At":"2"}]`},
	}
	store := &memMarkers{m: map[string]recipe.Marker{}}
	r := newReader(t, d, store, testRecipe("scan", recipe.Scanner))
	if _, err := r.Pass(context.Background()); err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	if len(d.flaws) != 3 {
		t.Fatalf("pass 1 raised %d, want 3", len(d.flaws))
	}
	if got := store.m["scan"]; got.Cursor != "2" || len(got.AtCursor) != 2 {
		t.Fatalf("marker = %+v", got)
	}

	// A restart: a new reader, the same store. The tool returns the same rows
	// and one new row that shares the cursor of the marker.
	d.results["scan"] = `[{"ID":"a","At":"1"},{"ID":"b","At":"2"},{"ID":"c","At":"2"},{"ID":"d","At":"2"},{"ID":"e","At":"3"}]`
	d.flaws = nil
	r2 := newReader(t, d, store, testRecipe("scan", recipe.Scanner))
	sum, err := r2.Pass(context.Background())
	if err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if len(d.flaws) != 2 || d.flaws[0].Item.ID != "d" || d.flaws[1].Item.ID != "e" || sum.Skipped != 3 {
		t.Fatalf("pass 2 raised %+v, sum %+v", d.flaws, sum)
	}
	if d.args[len(d.args)-1]["after"] != "2" {
		t.Fatalf("the call did not carry the marker: %v", d.args)
	}
}

// TestMarkerStopsAtTheFirstRefusal: the marker never moves past a result that
// the daemon refused, so the next pass reads it again.
func TestMarkerStopsAtTheFirstRefusal(t *testing.T) {
	d := &fakeDaemon{
		tools:   []Tool{{"edr", "list"}, {"scan", "list"}},
		results: map[string]string{"edr": `[{"ID":"1","At":"1"},{"ID":"2","At":"2"},{"ID":"3","At":"3"}]`, "scan": `[{"ID":"9","At":"1"}]`},
		failOn:  "2",
	}
	store := &memMarkers{m: map[string]recipe.Marker{}}
	r := newReader(t, d, store, testRecipe("edr", recipe.EDR), testRecipe("scan", recipe.Scanner))
	sum, err := r.Pass(context.Background())
	if !errors.Is(err, errBoom) || len(sum.Failed) != 1 || sum.Failed[0] != "edr" {
		t.Fatalf("err=%v sum=%+v", err, sum)
	}
	if store.m["edr"].Cursor != "1" {
		t.Fatalf("marker = %+v, want it at the last accepted result", store.m["edr"])
	}
	if len(d.flaws) != 1 {
		t.Fatal("one connector failing must not stop the others")
	}
}

func TestBadResultsFailTheConnector(t *testing.T) {
	for name, body := range map[string]string{
		"no id":     `[{"ID":"","At":"1"}]`,
		"no cursor": `[{"ID":"1","At":""}]`,
		"not json":  `{`,
	} {
		t.Run(name, func(t *testing.T) {
			d := &fakeDaemon{tools: []Tool{{"scan", "list"}}, results: map[string]string{"scan": body}}
			store := &memMarkers{m: map[string]recipe.Marker{}}
			r := newReader(t, d, store, testRecipe("scan", recipe.Scanner))
			if _, err := r.Pass(context.Background()); err == nil {
				t.Fatal("want an error")
			}
			if len(d.flaws) != 0 || store.saves != 0 {
				t.Fatal("a bad result must hand over nothing")
			}
		})
	}
}

func TestNewRequiresCollaborators(t *testing.T) {
	if _, err := New(nil, nil, nil, nil); err == nil {
		t.Fatal("want an error")
	}
}

func TestRunRejectsNoInterval(t *testing.T) {
	d := &fakeDaemon{}
	r := newReader(t, d, &memMarkers{m: map[string]recipe.Marker{}})
	if err := r.Run(context.Background(), 0); err == nil {
		t.Fatal("want an error")
	}
}

func TestRunStopsWithTheContext(t *testing.T) {
	d := &fakeDaemon{}
	r := newReader(t, d, &memMarkers{m: map[string]recipe.Marker{}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Run(ctx, 1); err != nil {
		t.Fatalf("run: %v", err)
	}
}
