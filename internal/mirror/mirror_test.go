// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mirror

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/intake-agent/internal/intake"
)

type fakeCaller struct{ tools []intake.Tool }

func (c *fakeCaller) Tools(context.Context) ([]intake.Tool, error) { return c.tools, nil }

func (c *fakeCaller) Invoke(context.Context, string, string, map[string]any) (intake.Call, error) {
	return intake.Call{}, errors.New("the fake adapter calls no tool")
}

type fakeSource struct{ items []Item }

func (s *fakeSource) Items(context.Context) ([]Item, error) { return s.items, nil }

// fakeTicketTool is a ticket tool in memory. It keeps one ticket for each item.
type fakeTicketTool struct {
	connector string
	tickets   map[string]*Ticket
	opened    []Item
	closes    int
	findErr   error
}

func newTool() *fakeTicketTool {
	return &fakeTicketTool{connector: "jira", tickets: map[string]*Ticket{}}
}

func (f *fakeTicketTool) Connector() string { return f.connector }

func (f *fakeTicketTool) Find(_ context.Context, _ intake.Caller, it Item) (Ticket, bool, error) {
	if f.findErr != nil {
		return Ticket{}, false, f.findErr
	}
	t, ok := f.tickets[it.ID]
	if !ok {
		return Ticket{}, false, nil
	}
	return *t, true, nil
}

func (f *fakeTicketTool) Open(_ context.Context, _ intake.Caller, it Item) (Ticket, error) {
	t := &Ticket{Ref: fmt.Sprintf("SEC-%d", len(f.tickets)+1), Status: it.Status}
	f.tickets[it.ID] = t
	f.opened = append(f.opened, it)
	return *t, nil
}

func (f *fakeTicketTool) Update(_ context.Context, _ intake.Caller, _ Ticket, it Item) error {
	f.tickets[it.ID].Status = it.Status
	f.tickets[it.ID].Closed = false
	return nil
}

func (f *fakeTicketTool) Close(_ context.Context, _ intake.Caller, _ Ticket, it Item) error {
	f.tickets[it.ID].Status = it.Status
	f.tickets[it.ID].Closed = true
	f.closes++
	return nil
}

func finding(status string) Item {
	return Item{Kind: KindFinding, ID: "f-1", Title: "Open port", Severity: "high", Status: status,
		URL: "https://console.example/findings/f-1"}
}

func newMirror(t *testing.T, tool Adapter, items []Item, connectors ...string) (*Mirror, *fakeSource, *bytes.Buffer) {
	t.Helper()
	tools := make([]intake.Tool, 0, len(connectors))
	for _, c := range connectors {
		tools = append(tools, intake.Tool{Connector: c, Name: "any"})
	}
	src := &fakeSource{items: items}
	var logs bytes.Buffer
	m, err := New(&fakeCaller{tools: tools}, src, []Adapter{tool}, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return m, src, &logs
}

func TestANewFindingOpensOneTicketWithSeverityAndLink(t *testing.T) {
	tool := newTool()
	m, _, _ := newMirror(t, tool, []Item{finding("open")}, "jira")
	for pass := range 3 {
		sum, err := m.Pass(context.Background())
		if err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		wantOpened := 0
		if pass == 0 {
			wantOpened = 1
		}
		if sum.Opened != wantOpened {
			t.Fatalf("pass %d: opened %d, want %d", pass, sum.Opened, wantOpened)
		}
	}
	if len(tool.opened) != 1 {
		t.Fatalf("the tool opened %d tickets, want 1", len(tool.opened))
	}
	got := tool.opened[0]
	if got.Severity != "high" || got.URL != "https://console.example/findings/f-1" {
		t.Fatalf("the ticket lacks the severity or the link: %+v", got)
	}
}

func TestEachStatusChangeUpdatesTheTicketAndVerifiedClosesIt(t *testing.T) {
	tool := newTool()
	m, src, _ := newMirror(t, tool, []Item{finding("open")}, "jira")
	steps := []struct {
		status              string
		updated, closed     int
		wantStatus          string
		wantClosed          bool
		wantClosesOnAdapter int
	}{
		{"open", 0, 0, "open", false, 0},
		{"fixing", 1, 0, "fixing", false, 0},
		{"fixing", 0, 0, "fixing", false, 0},
		{"fixed", 1, 0, "fixed", false, 0},
		{"verified", 0, 1, "verified", true, 1},
		{"verified", 0, 0, "verified", true, 1},
	}
	for _, s := range steps {
		src.items = []Item{finding(s.status)}
		sum, err := m.Pass(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", s.status, err)
		}
		tk := tool.tickets["f-1"]
		if sum.Updated != s.updated || sum.Closed != s.closed || tk.Status != s.wantStatus ||
			tk.Closed != s.wantClosed || tool.closes != s.wantClosesOnAdapter {
			t.Fatalf("status %s: summary %+v, ticket %+v, closes %d", s.status, sum, *tk, tool.closes)
		}
	}
	if len(tool.opened) != 1 {
		t.Fatalf("the tool opened %d tickets, want 1", len(tool.opened))
	}
}

func TestAFindingThatIsAlreadyVerifiedGetsNoTicket(t *testing.T) {
	tool := newTool()
	m, _, _ := newMirror(t, tool, []Item{finding("verified")}, "jira")
	sum, err := m.Pass(context.Background())
	if err != nil || sum.NoTicket != 1 || len(tool.opened) != 0 {
		t.Fatalf("summary %+v, err %v, opened %d", sum, err, len(tool.opened))
	}
}

func TestAnIncidentGetsATicketAndItsResolutionClosesIt(t *testing.T) {
	tool := newTool()
	inc := Item{Kind: KindIncident, ID: "i-1", Title: "Phishing", Severity: "critical", Status: "open"}
	m, src, _ := newMirror(t, tool, []Item{inc}, "jira")
	if _, err := m.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	inc.Status = "resolved"
	src.items = []Item{inc}
	if _, err := m.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !tool.tickets["i-1"].Closed {
		t.Fatal("the ticket of the resolved incident is open")
	}
}

func TestATenantWithNoTicketConnectorGetsNoErrorAndOneLog(t *testing.T) {
	tool := newTool()
	// The tenant has a connector, but not the one of the adapter.
	m, _, logs := newMirror(t, tool, []Item{finding("open")}, "wiz")
	for range 3 {
		sum, err := m.Pass(context.Background())
		if err != nil {
			t.Fatalf("a missing ticket connector is not an error: %v", err)
		}
		if !sum.NoConnector || sum.Opened != 0 {
			t.Fatalf("summary %+v", sum)
		}
	}
	if len(tool.tickets) != 0 {
		t.Fatal("the mirror wrote a ticket with no connector")
	}
	if n := strings.Count(logs.String(), "no ticket connector"); n != 1 {
		t.Fatalf("the mirror logged %d times, want 1:\n%s", n, logs)
	}
}

func TestARefusedGrantStopsThePass(t *testing.T) {
	tool := newTool()
	tool.findErr = fmt.Errorf("call: %w", intake.ErrGrant)
	m, _, _ := newMirror(t, tool, []Item{finding("open")}, "jira")
	if _, err := m.Pass(context.Background()); !errors.Is(err, intake.ErrGrant) {
		t.Fatalf("want ErrGrant, got %v", err)
	}
}

func TestOneFailedItemDoesNotStopTheOthers(t *testing.T) {
	tool := newTool()
	bad := finding("open")
	bad.ID = "bad"
	m, _, _ := newMirror(t, &failOpen{fakeTicketTool: tool, id: "bad"}, []Item{bad, finding("open")}, "jira")
	sum, err := m.Pass(context.Background())
	if err == nil || sum.Opened != 1 {
		t.Fatalf("summary %+v, err %v", sum, err)
	}
}

type failOpen struct {
	*fakeTicketTool
	id string
}

func (f *failOpen) Open(ctx context.Context, c intake.Caller, it Item) (Ticket, error) {
	if it.ID == f.id {
		return Ticket{}, errors.New("vendor down")
	}
	return f.fakeTicketTool.Open(ctx, c, it)
}

func TestNewNeedsEachPart(t *testing.T) {
	if _, err := New(nil, &fakeSource{}, []Adapter{newTool()}, nil); err == nil {
		t.Fatal("want an error")
	}
	if _, err := New(&fakeCaller{}, &fakeSource{}, nil, nil); err == nil {
		t.Fatal("want an error")
	}
}
