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
	out := make([]intake.Tool, 0, len(s.connectors))
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
	handlers := map[string]func(map[string]any) (map[string]any, error){
		"create_ticket":  s.create,
		"update_ticket":  s.update,
		"add_comment":    s.comment,
		"close_ticket":   s.closeTicket,
		"search_tickets": s.search,
	}
	h, ok := handlers[tool]
	if !ok {
		return intake.Call{}, fmt.Errorf("no tool %q", tool)
	}
	out, err := h(a)
	if err != nil {
		return intake.Call{}, err
	}
	return result(out), nil
}

func str(a map[string]any, k string) string { v, _ := a[k].(string); return v }

func (s *ticketServer) create(a map[string]any) (map[string]any, error) {
	titleLen := len([]rune(str(a, "title")))
	if str(a, "title") == "" || titleLen > 255 || str(a, "description") == "" || len(str(a, "description")) > 32000 {
		return nil, errors.New("create_ticket: bad title or description")
	}
	if p := str(a, "priority"); p != "" && p != "low" && p != "medium" && p != "high" && p != "critical" {
		return nil, errors.New("create_ticket: bad priority")
	}
	labels, _ := a["labels"].([]string)
	for _, l := range labels {
		if !srvLabel.MatchString(l) {
			return nil, fmt.Errorf("create_ticket: bad label %q", l)
		}
	}
	key := str(a, "dedup_key")
	if key != "" && (len(key) > 100 || !srvDedup.MatchString(key)) {
		return nil, errors.New("create_ticket: bad dedup_key")
	}
	for _, t := range s.tickets {
		if key != "" && t.key == key {
			return map[string]any{"ticket_id": t.id, "existing": true}, nil
		}
	}
	t := &srvTicket{id: fmt.Sprintf("T%d", len(s.tickets)+1), key: key, title: str(a, "title"),
		description: str(a, "description"), priority: str(a, "priority"), queue: str(a, "queue"), labels: labels}
	s.tickets = append(s.tickets, t)
	if s.failAfterCreate {
		s.failAfterCreate = false
		return nil, errors.New("create_ticket: timeout")
	}
	return map[string]any{"ticket_id": t.id, "number": "N-" + t.id, "url": "https://t/" + t.id, "existing": false}, nil
}

func (s *ticketServer) update(a map[string]any) (map[string]any, error) {
	t, err := s.find(str(a, "ticket_id"))
	if err != nil {
		return nil, err
	}
	if t.closed {
		return nil, errors.New("update_ticket: the ticket is closed")
	}
	if str(a, "title") == "" && str(a, "description") == "" && str(a, "priority") == "" {
		return nil, errors.New("update_ticket: give at least one field")
	}
	if v := str(a, "title"); v != "" {
		t.title = v
	}
	if v := str(a, "priority"); v != "" {
		t.priority = v
	}
	return map[string]any{"ticket_id": t.id, "action": "updated", "status": "open"}, nil
}

func (s *ticketServer) comment(a map[string]any) (map[string]any, error) {
	t, err := s.find(str(a, "ticket_id"))
	if err != nil || str(a, "body") == "" {
		return nil, errors.New("add_comment: bad input")
	}
	t.comments = append(t.comments, str(a, "body"))
	return map[string]any{"ticket_id": t.id, "action": "commented"}, nil
}

func (s *ticketServer) closeTicket(a map[string]any) (map[string]any, error) {
	t, err := s.find(str(a, "ticket_id"))
	if err != nil || str(a, "resolution") == "" {
		return nil, errors.New("close_ticket: bad input")
	}
	t.closed, t.resolution = true, str(a, "resolution")
	return map[string]any{"ticket_id": t.id, "action": "closed", "status": "closed"}, nil
}

func (s *ticketServer) search(a map[string]any) (map[string]any, error) {
	var found []map[string]any
	for _, t := range s.tickets {
		if s.searchBlind || (str(a, "label") != "" && !contains(t.labels, str(a, "label"))) {
			continue
		}
		if st := str(a, "status"); (st == "" || st == "open") && t.closed || st == "closed" && !t.closed {
			continue
		}
		if q := str(a, "queue"); q != "" && t.queue != q {
			continue
		}
		found = append(found, map[string]any{"ticket_id": t.id, "title": t.title, "closed": t.closed})
	}
	return map[string]any{"tickets": found, "count": len(found)}, nil
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
