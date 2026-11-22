// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pager

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/intake-agent/internal/intake"
)

type fakeCaller struct{ tools []intake.Tool }

func (c *fakeCaller) Tools(context.Context) ([]intake.Tool, error) { return c.tools, nil }

func (c *fakeCaller) Invoke(context.Context, string, string, map[string]any) (intake.Call, error) {
	return intake.Call{}, errors.New("the fake adapter calls no tool")
}

type fakeSource struct {
	items []Waiting
	limit time.Duration
}

func (s *fakeSource) Waiting(context.Context) ([]Waiting, error)   { return s.items, nil }
func (s *fakeSource) Limit(context.Context) (time.Duration, error) { return s.limit, nil }

// fakePaging is a paging tool in memory. It holds the key of each page.
type fakePaging struct {
	pages   []Waiting
	keys    map[string]bool
	pageErr error
	findErr error
}

func (f *fakePaging) Connector() string { return "pagerduty" }

func (f *fakePaging) Paged(_ context.Context, _ intake.Caller, key string) (bool, error) {
	return f.keys[key], f.findErr
}

func (f *fakePaging) Page(_ context.Context, _ intake.Caller, w Waiting, key string) error {
	if f.pageErr != nil {
		return f.pageErr
	}
	f.pages = append(f.pages, w)
	f.keys[key] = true
	return nil
}

var t0 = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

func wait(id string, waited time.Duration) Waiting {
	return Waiting{Kind: "merge_refused", ID: id, Since: t0, Waited: waited, URL: "https://console.example/findings/" + id}
}

func newPager(t *testing.T, tool Adapter, src *fakeSource, connectors ...string) (*Pager, *bytes.Buffer) {
	t.Helper()
	tools := make([]intake.Tool, 0, len(connectors))
	for _, c := range connectors {
		tools = append(tools, intake.Tool{Connector: c, Name: "any"})
	}
	var logs bytes.Buffer
	p, err := New(&fakeCaller{tools: tools}, src, []Adapter{tool}, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return p, &logs
}

func TestAnItemOverTheLimitGivesOnePageWithALink(t *testing.T) {
	tool := &fakePaging{keys: map[string]bool{}}
	src := &fakeSource{limit: time.Hour, items: []Waiting{wait("f-1", 2*time.Hour), wait("f-2", 10*time.Minute)}}
	p, _ := newPager(t, tool, src, "pagerduty")
	for pass := range 3 {
		if _, err := p.Pass(context.Background()); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
	}
	if len(tool.pages) != 1 {
		t.Fatalf("the tool got %d pages, want 1", len(tool.pages))
	}
	if tool.pages[0].ID != "f-1" || !strings.HasSuffix(tool.pages[0].URL, "/f-1") {
		t.Fatalf("wrong page: %+v", tool.pages[0])
	}
}

func TestARestartSendsNoSecondPage(t *testing.T) {
	tool := &fakePaging{keys: map[string]bool{}}
	src := &fakeSource{limit: time.Hour, items: []Waiting{wait("f-1", 2*time.Hour)}}
	p1, _ := newPager(t, tool, src, "pagerduty")
	if _, err := p1.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A new process has no memory. The paging tool holds the page.
	p2, _ := newPager(t, tool, src, "pagerduty")
	sum, err := p2.Pass(context.Background())
	if err != nil || sum.Already != 1 || len(tool.pages) != 1 {
		t.Fatalf("summary %+v, err %v, pages %d", sum, err, len(tool.pages))
	}
}

func TestAnItemThatWaitsAgainGetsANewPage(t *testing.T) {
	tool := &fakePaging{keys: map[string]bool{}}
	src := &fakeSource{limit: time.Hour, items: []Waiting{wait("f-1", 2*time.Hour)}}
	p, _ := newPager(t, tool, src, "pagerduty")
	if _, err := p.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	src.items = nil // the wait ended
	if _, err := p.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	again := wait("f-1", 2*time.Hour)
	again.Since = t0.Add(48 * time.Hour)
	src.items = []Waiting{again}
	if _, err := p.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(tool.pages) != 2 {
		t.Fatalf("the tool got %d pages, want 2", len(tool.pages))
	}
}

func TestAFailedPageIsRetriedOnTheNextPass(t *testing.T) {
	tool := &fakePaging{keys: map[string]bool{}, pageErr: errors.New("vendor down")}
	src := &fakeSource{limit: time.Hour, items: []Waiting{wait("f-1", 2*time.Hour)}}
	p, _ := newPager(t, tool, src, "pagerduty")
	if _, err := p.Pass(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	tool.pageErr = nil
	if _, err := p.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(tool.pages) != 1 {
		t.Fatalf("the tool got %d pages, want 1", len(tool.pages))
	}
}

func TestATenantWithNoPagingConnectorGetsNoErrorAndOneLog(t *testing.T) {
	tool := &fakePaging{keys: map[string]bool{}}
	src := &fakeSource{limit: time.Hour, items: []Waiting{wait("f-1", 2*time.Hour)}}
	p, logs := newPager(t, tool, src, "jira")
	for range 3 {
		sum, err := p.Pass(context.Background())
		if err != nil || !sum.NoConnector {
			t.Fatalf("summary %+v, err %v", sum, err)
		}
	}
	if len(tool.pages) != 0 {
		t.Fatal("the pager paged with no connector")
	}
	if n := strings.Count(logs.String(), "no paging connector"); n != 1 {
		t.Fatalf("the pager logged %d times, want 1", n)
	}
}

func TestDefaultLimitIsFourHours(t *testing.T) {
	if DefaultLimit != 4*time.Hour {
		t.Fatalf("DefaultLimit = %s, want 4h", DefaultLimit)
	}
}

func TestATenantWithNoLimitGetsTheDefault(t *testing.T) {
	tool := &fakePaging{keys: map[string]bool{}}
	src := &fakeSource{items: []Waiting{wait("short", 3*time.Hour), wait("long", 5*time.Hour)}}
	p, _ := newPager(t, tool, src, "pagerduty")
	sum, err := p.Pass(context.Background())
	if err != nil || sum.Limit != DefaultLimit {
		t.Fatalf("summary %+v, err %v", sum, err)
	}
	if len(tool.pages) != 1 || tool.pages[0].ID != "long" {
		t.Fatalf("pages %+v, want one page for the wait of 5h", tool.pages)
	}
}

func TestATenantLimitReplacesTheDefault(t *testing.T) {
	tool := &fakePaging{keys: map[string]bool{}}
	src := &fakeSource{limit: time.Hour, items: []Waiting{wait("a", 90*time.Minute)}}
	p, _ := newPager(t, tool, src, "pagerduty")
	if sum, err := p.Pass(context.Background()); err != nil || sum.Limit != time.Hour || len(tool.pages) != 1 {
		t.Fatalf("summary %+v, err %v, pages %d", sum, err, len(tool.pages))
	}
}

func TestAWaitEqualToTheLimitGivesNoPage(t *testing.T) {
	tool := &fakePaging{keys: map[string]bool{}}
	src := &fakeSource{limit: time.Hour, items: []Waiting{wait("f-1", time.Hour)}}
	p, _ := newPager(t, tool, src, "pagerduty")
	if _, err := p.Pass(context.Background()); err != nil || len(tool.pages) != 0 {
		t.Fatalf("err %v, pages %d", err, len(tool.pages))
	}
}

func TestARefusedGrantStopsThePass(t *testing.T) {
	tool := &fakePaging{keys: map[string]bool{}, findErr: fmt.Errorf("call: %w", intake.ErrGrant)}
	src := &fakeSource{limit: time.Hour, items: []Waiting{wait("f-1", 2*time.Hour)}}
	p, _ := newPager(t, tool, src, "pagerduty")
	if _, err := p.Pass(context.Background()); !errors.Is(err, intake.ErrGrant) {
		t.Fatalf("want ErrGrant, got %v", err)
	}
}

func TestKeyIsStablePerWait(t *testing.T) {
	a, b := wait("f-1", time.Hour), wait("f-1", 5*time.Hour)
	if Key(a) != Key(b) {
		t.Fatal("two reads of one wait must give one key")
	}
	c := a
	c.Kind = "next_scan"
	if Key(a) == Key(c) {
		t.Fatal("two kinds must give two keys")
	}
}

func TestNoAdapterShips(t *testing.T) {
	if _, err := Shipped(); !errors.Is(err, ErrNoAdapters) {
		t.Fatalf("want ErrNoAdapters, got %v", err)
	}
}
