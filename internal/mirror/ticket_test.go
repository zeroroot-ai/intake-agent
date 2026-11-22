// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mirror

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/zeroroot-ai/intake-agent/internal/intake"
)

// ticketServer is a mock of a ticket server of the connectors repo. It follows the
// section "Ticket contract" of its README: the tool names, the arguments, the
// limits, the dedup_key and the result fields.
type ticketServer struct {
	connectors []string
	tickets    []*srvTicket
	calls      []string
	// failAfterCreate makes create_ticket make the ticket and then fail, as a
	// timeout after the vendor took the call does.
	failAfterCreate bool
	// searchBlind makes search_tickets find nothing, as a vendor that has not
	// indexed the ticket yet does.
	searchBlind bool
	grantErr    error
}

type srvTicket struct {
	id, key, title, description, priority, queue, resolution string
	labels                                                   []string
	comments                                                 []string
	closed                                                   bool
}

var (
	srvLabel = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,50}$`)
	srvDedup = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@=+-]*$`)
)

func (s *ticketServer) Tools(context.Context) ([]intake.Tool, error) {
	var out []intake.Tool
	for _, c := range s.connectors {
		out = append(out, intake.Tool{Connector: c, Name: "create_ticket"})
	}
	return out, nil
}

func (s *ticketServer) find(id string) (*srvTicket, error) {
	for _, t := range s.tickets {
		if t.id == id {
			return t, nil
		}
	}
	return nil, fmt.Errorf("no ticket %q", id)
}

func (s *ticketServer) Invoke(_ context.Context, connector, tool string, a map[string]any) (intake.Call, error) {
	if s.grantErr != nil {
		return intake.Call{}, s.grantErr
	}
	s.calls = append(s.calls, connector+"/"+tool)
	str := func(k string) string { v, _ := a[k].(string); return v }
	out := map[string]any{}
	switch tool {
	case "create_ticket":
		titleLen := len([]rune(str("title")))
		if str("title") == "" || titleLen > 255 || str("description") == "" || len(str("description")) > 32000 {
			return intake.Call{}, errors.New("create_ticket: bad title or description")
		}
		if p := str("priority"); p != "" && p != "low" && p != "medium" && p != "high" && p != "critical" {
			return intake.Call{}, errors.New("create_ticket: bad priority")
		}
		labels, _ := a["labels"].([]string)
		for _, l := range labels {
			if !srvLabel.MatchString(l) {
				return intake.Call{}, fmt.Errorf("create_ticket: bad label %q", l)
			}
		}
		key := str("dedup_key")
		if key != "" && (len(key) > 100 || !srvDedup.MatchString(key)) {
			return intake.Call{}, errors.New("create_ticket: bad dedup_key")
		}
		for _, t := range s.tickets {
			if key != "" && t.key == key {
				out["ticket_id"], out["existing"] = t.id, true
				return result(out), nil
			}
		}
		t := &srvTicket{id: fmt.Sprintf("T%d", len(s.tickets)+1), key: key, title: str("title"),
			description: str("description"), priority: str("priority"), queue: str("queue"), labels: labels}
		s.tickets = append(s.tickets, t)
		if s.failAfterCreate {
			s.failAfterCreate = false
			return intake.Call{}, errors.New("create_ticket: timeout")
		}
		out["ticket_id"], out["number"], out["url"], out["existing"] = t.id, "N-"+t.id, "https://t/"+t.id, false
	case "update_ticket":
		t, err := s.find(str("ticket_id"))
		if err != nil {
			return intake.Call{}, err
		}
		if t.closed {
			return intake.Call{}, errors.New("update_ticket: the ticket is closed")
		}
		if str("title") == "" && str("description") == "" && str("priority") == "" {
			return intake.Call{}, errors.New("update_ticket: give at least one field")
		}
		if v := str("title"); v != "" {
			t.title = v
		}
		if v := str("priority"); v != "" {
			t.priority = v
		}
		out["ticket_id"], out["action"], out["status"] = t.id, "updated", "open"
	case "add_comment":
		t, err := s.find(str("ticket_id"))
		if err != nil || str("body") == "" {
			return intake.Call{}, errors.New("add_comment: bad input")
		}
		t.comments = append(t.comments, str("body"))
		out["ticket_id"], out["action"] = t.id, "commented"
	case "close_ticket":
		t, err := s.find(str("ticket_id"))
		if err != nil || str("resolution") == "" {
			return intake.Call{}, errors.New("close_ticket: bad input")
		}
		t.closed, t.resolution = true, str("resolution")
		out["ticket_id"], out["action"], out["status"] = t.id, "closed", "closed"
	case "search_tickets":
		var found []map[string]any
		for _, t := range s.tickets {
			if s.searchBlind || (str("label") != "" && !contains(t.labels, str("label"))) {
				continue
			}
			if st := str("status"); (st == "" || st == "open") && t.closed || st == "closed" && !t.closed {
				continue
			}
			if q := str("queue"); q != "" && t.queue != q {
				continue
			}
			found = append(found, map[string]any{"ticket_id": t.id, "title": t.title, "closed": t.closed})
		}
		out["tickets"], out["count"] = found, len(found)
	default:
		return intake.Call{}, fmt.Errorf("no tool %q", tool)
	}
	return result(out), nil
}

func result(v any) intake.Call {
	b, _ := json.Marshal(v)
	return intake.Call{JSON: b}
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func newTicketMirror(t *testing.T, s *ticketServer, src *fakeSource, queue string) *Mirror {
	t.Helper()
	m, err := New(s, src, Adapters(queue), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func pass(t *testing.T, m *Mirror) Summary {
	t.Helper()
	sum, err := m.Pass(context.Background())
	if err != nil {
		t.Fatalf("pass: %v", err)
	}
	return sum
}

func TestTheTicketLifecycleThroughTheContract(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	src := &fakeSource{items: []Item{finding("open")}}
	m := newTicketMirror(t, srv, src, "SEC")

	pass(t, m)
	if len(srv.tickets) != 1 {
		t.Fatalf("%d tickets, want 1", len(srv.tickets))
	}
	tk := srv.tickets[0]
	if tk.key != "f-1" || !contains(tk.labels, "gibson:f-1") || tk.queue != "SEC" || tk.priority != "high" {
		t.Fatalf("the ticket is not made from the contract: %+v", *tk)
	}
	if !strings.HasPrefix(tk.title, "[open] Open port") ||
		!strings.Contains(tk.description, "https://console.example/findings/f-1") ||
		!strings.Contains(tk.description, "Severity: high") {
		t.Fatalf("title %q, description %q", tk.title, tk.description)
	}

	src.items = []Item{finding("fixing")}
	pass(t, m)
	if !strings.HasPrefix(tk.title, "[fixing] ") || len(tk.comments) != 1 || !strings.Contains(tk.comments[0], "fixing") {
		t.Fatalf("title %q, comments %q", tk.title, tk.comments)
	}
	before := len(srv.calls)
	pass(t, m) // no change: only the search runs
	if got := srv.calls[before:]; len(got) != 1 || got[0] != "jira/search_tickets" {
		t.Fatalf("an unchanged pass made the calls %v", got)
	}

	src.items = []Item{finding("verified")}
	pass(t, m)
	if !tk.closed || !strings.Contains(tk.resolution, "verified") || len(srv.tickets) != 1 {
		t.Fatalf("closed %v, resolution %q, tickets %d", tk.closed, tk.resolution, len(srv.tickets))
	}
	before = len(srv.calls)
	pass(t, m)
	if got := srv.calls[before:]; len(got) != 1 {
		t.Fatalf("a pass after the close made the calls %v", got)
	}
}

func TestARestartOpensNoSecondTicket(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	src := &fakeSource{items: []Item{finding("open")}}
	pass(t, newTicketMirror(t, srv, src, ""))
	pass(t, newTicketMirror(t, srv, src, "")) // a new process has no memory
	if len(srv.tickets) != 1 {
		t.Fatalf("%d tickets, want 1", len(srv.tickets))
	}
}

func TestATimeoutAfterTheCreateOpensNoSecondTicket(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}, failAfterCreate: true}
	src := &fakeSource{items: []Item{finding("open")}}
	m := newTicketMirror(t, srv, src, "")
	if _, err := m.Pass(context.Background()); err == nil {
		t.Fatal("want the timeout")
	}
	pass(t, m)
	if len(srv.tickets) != 1 {
		t.Fatalf("%d tickets, want 1", len(srv.tickets))
	}
}

// TestADedupKeyHoldsWhenTheSearchDoesNotSeeTheTicket: the vendor has not indexed the
// ticket, so Find says that none exists. create_ticket with the dedup_key still
// returns the first ticket.
func TestADedupKeyHoldsWhenTheSearchDoesNotSeeTheTicket(t *testing.T) {
	srv := &ticketServer{connectors: []string{"servicenow"}}
	src := &fakeSource{items: []Item{finding("open")}}
	m := newTicketMirror(t, srv, src, "")
	pass(t, m)
	srv.searchBlind = true
	for range 3 {
		pass(t, m)
	}
	if len(srv.tickets) != 1 {
		t.Fatalf("%d tickets, want 1", len(srv.tickets))
	}
}

func TestEachTicketConnectorIsServedByTheSameAdapterShape(t *testing.T) {
	for _, c := range []string{"jira", "servicenow"} {
		srv := &ticketServer{connectors: []string{c}}
		pass(t, newTicketMirror(t, srv, &fakeSource{items: []Item{finding("open")}}, ""))
		if len(srv.tickets) != 1 || srv.calls[0] != c+"/search_tickets" {
			t.Fatalf("%s: tickets %d, calls %v", c, len(srv.tickets), srv.calls)
		}
	}
}

func TestAnIncidentGetsATicketToo(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	inc := Item{Kind: KindIncident, ID: "i-1", Title: "Phishing", Severity: "critical", Status: "open"}
	src := &fakeSource{items: []Item{inc}}
	m := newTicketMirror(t, srv, src, "")
	pass(t, m)
	inc.Status = "resolved"
	src.items = []Item{inc}
	pass(t, m)
	if tk := srv.tickets[0]; tk.priority != "critical" || !tk.closed {
		t.Fatalf("%+v", *tk)
	}
}

func TestAClosedTicketOfAnItemThatOpensAgainIsAnErrorAndNotANewTicket(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	src := &fakeSource{items: []Item{finding("open")}}
	m := newTicketMirror(t, srv, src, "")
	pass(t, m)
	src.items = []Item{finding("verified")}
	pass(t, m)
	src.items = []Item{finding("open")}
	if _, err := m.Pass(context.Background()); err == nil || !strings.Contains(err.Error(), "no call to reopen") {
		t.Fatalf("err = %v", err)
	}
	if len(srv.tickets) != 1 {
		t.Fatalf("%d tickets, want 1", len(srv.tickets))
	}
}

func TestAnIDThatTheContractCannotCarryMakesNoCall(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	for _, id := range []string{"has space", "has/slash", strings.Repeat("a", 44), ""} {
		it := finding("open")
		it.ID = id
		m := newTicketMirror(t, srv, &fakeSource{items: []Item{it}}, "")
		if _, err := m.Pass(context.Background()); err == nil {
			t.Errorf("id %q: want an error", id)
		}
	}
	if len(srv.calls) != 0 {
		t.Fatalf("calls %v, want none", srv.calls)
	}
}

func TestPriorityAndTitleLimits(t *testing.T) {
	for in, want := range map[string]string{
		"critical": "critical", "HIGH": "high", "medium": "medium", "low": "low", "info": "low", "": "medium", "x": "medium",
	} {
		if got := priority(in); got != want {
			t.Errorf("priority(%q) = %q, want %q", in, got, want)
		}
	}
	long := finding("open")
	long.Title = strings.Repeat("é", 400) + "\nline"
	if n := len([]rune(title(long))); n != maxTitle {
		t.Fatalf("title has %d characters, want %d", n, maxTitle)
	}
	long.Title = "a\n  b\tc"
	if got := title(long); got != "[open] a b c" {
		t.Fatalf("title = %q", got)
	}
}

func TestAGrantRefusalKeepsItsChainThroughTheAdapter(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}, grantErr: fmt.Errorf("daemon: %w", intake.ErrGrant)}
	m := newTicketMirror(t, srv, &fakeSource{items: []Item{finding("open")}}, "")
	if _, err := m.Pass(context.Background()); !errors.Is(err, intake.ErrGrant) {
		t.Fatalf("err = %v", err)
	}
}
