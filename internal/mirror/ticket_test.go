// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mirror

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/zeroroot-ai/intake-agent/internal/intake"
)

// ticketServer is a mock of a ticket server of the connectors repo. It follows the
// section "Ticket contract" of its README and applies the refusals of the real
// servers. Each refusal is copied from the file that is named at it, in
// zeroroot-ai/connectors at release v0.4.0.
//
// The search follows internal/ticket/ticket.go (SearchInput.DedupKey, StatusOf), and
// jira/server.go and servicenow/server.go (the dedup_key condition) of v0.4.0. A
// search by dedup_key gives the tickets oldest first, and the status defaults to any.
type ticketServer struct {
	connectors []string
	tickets    []*srvTicket
	calls      []string
	args       []map[string]any
	// failAfterCreate makes create_ticket make the ticket and then fail, as a
	// timeout after the vendor took the call does.
	failAfterCreate bool
	// searchBlind makes search_tickets find nothing, as a vendor that has not
	// indexed the ticket yet does.
	searchBlind bool
	grantErr    error
}

type srvTicket struct {
	id, key, title, description, priority, queue, resolution, createdAt string
	comments                                                            []string
	closed                                                              bool
}

var (
	// internal/ticket/ticket.go: dedupFormat. internal/kit/validate.go: Hex32.
	srvDedup = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@=+-]*$`)
	srvHex32 = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	// jira/server.go: projectKey.
	srvProject = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,9}$`)
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
	s.args = append(s.args, a)
	// servicenow/server.go:241 and :396: ServiceNow has no labels on an incident,
	// so a create with labels and a search with a label fail.
	if connector == "servicenow" && (len(strOrList(a["labels"])) > 0 || str(a, "label") != "") {
		return intake.Call{}, errors.New("ServiceNow has no labels on an incident. Leave labels out")
	}
	// The queue formats: jira/server.go:242 and :566, and checkID in servicenow/server.go.
	if q := str(a, "queue"); q != "" || (tool == "create_ticket" && connector == "jira") {
		if connector == "jira" && !srvProject.MatchString(q) {
			return intake.Call{}, errors.New("queue must be the key of a Jira project, for example SEC")
		}
		if connector == "servicenow" && !srvHex32.MatchString(q) {
			return intake.Call{}, errors.New("check queue: queue has the wrong format")
		}
	}
	handlers := map[string]func(string, map[string]any) (map[string]any, error){
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
	out, err := h(connector, a)
	if err != nil {
		return intake.Call{}, err
	}
	return result(out), nil
}

func str(a map[string]any, k string) string { v, _ := a[k].(string); return v }

func strOrList(v any) []string { l, _ := v.([]string); return l }

// checkTitle is CheckString of internal/kit/validate.go: not empty, at most limit
// bytes, valid UTF-8, no control character.
func checkTitle(field, v string, limit int) error {
	switch {
	case v == "":
		return fmt.Errorf("%s is required", field)
	case len(v) > limit:
		return fmt.Errorf("%s is longer than %d bytes", field, limit)
	case !utf8.ValidString(v):
		return fmt.Errorf("%s is not valid UTF-8", field)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s holds a control character", field)
		}
	}
	return nil
}

// checkLong is checkLong of internal/ticket/ticket.go: not blank, at most limit
// bytes, and no control character except a new line, a tab and a carriage return.
func checkLong(field, v string, limit int) error {
	switch {
	case strings.TrimSpace(v) == "":
		return fmt.Errorf("%s is required", field)
	case len(v) > limit:
		return fmt.Errorf("%s is longer than %d bytes", field, limit)
	}
	for _, r := range v {
		if (r < 0x20 && r != '\n' && r != '\t' && r != '\r') || r == 0x7f {
			return fmt.Errorf("%s holds a control character", field)
		}
	}
	return nil
}

func (s *ticketServer) create(_ string, a map[string]any) (map[string]any, error) {
	if err := checkTitle("title", str(a, "title"), 255); err != nil {
		return nil, err
	}
	if err := checkLong("description", str(a, "description"), 32000); err != nil {
		return nil, err
	}
	if p := str(a, "priority"); p != "" && p != "low" && p != "medium" && p != "high" && p != "critical" {
		return nil, errors.New("create_ticket: bad priority")
	}
	key := str(a, "dedup_key")
	if key != "" {
		if err := checkTitle("dedup_key", key, 100); err != nil || !srvDedup.MatchString(key) {
			return nil, errors.New("dedup_key has the wrong format")
		}
	}
	for _, t := range s.tickets {
		if key != "" && t.key == key {
			return map[string]any{"ticket_id": t.id, "existing": true}, nil
		}
	}
	t := &srvTicket{id: fmt.Sprintf("T%d", len(s.tickets)+1), key: key, title: str(a, "title"),
		description: str(a, "description"), priority: str(a, "priority"), queue: str(a, "queue"),
		createdAt: fmt.Sprintf("2026-11-21T10:%02d:00Z", len(s.tickets))}
	s.tickets = append(s.tickets, t)
	if s.failAfterCreate {
		s.failAfterCreate = false
		return nil, errors.New("create_ticket: timeout")
	}
	return map[string]any{"ticket_id": t.id, "number": "N-" + t.id, "url": "https://t/" + t.id, "existing": false}, nil
}

func (s *ticketServer) update(_ string, a map[string]any) (map[string]any, error) {
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
		if err := checkTitle("title", v, 255); err != nil {
			return nil, err
		}
		t.title = v
	}
	if v := str(a, "priority"); v != "" {
		t.priority = v
	}
	return map[string]any{"ticket_id": t.id, "action": "updated", "status": "open"}, nil
}

func (s *ticketServer) comment(_ string, a map[string]any) (map[string]any, error) {
	t, err := s.find(str(a, "ticket_id"))
	if err != nil {
		return nil, err
	}
	if err := checkLong("body", str(a, "body"), 32000); err != nil {
		return nil, err
	}
	t.comments = append(t.comments, str(a, "body"))
	return map[string]any{"ticket_id": t.id, "action": "commented"}, nil
}

func (s *ticketServer) closeTicket(_ string, a map[string]any) (map[string]any, error) {
	t, err := s.find(str(a, "ticket_id"))
	if err != nil {
		return nil, err
	}
	if err := checkLong("resolution", str(a, "resolution"), 32000); err != nil {
		return nil, err
	}
	t.closed, t.resolution = true, str(a, "resolution")
	return map[string]any{"ticket_id": t.id, "action": "closed", "status": "closed"}, nil
}

func (s *ticketServer) search(_ string, a map[string]any) (map[string]any, error) {
	if k := str(a, "dedup_key"); k != "" && (len(k) > 100 || !srvDedup.MatchString(k)) {
		return nil, errors.New("dedup_key has the wrong format")
	}
	// StatusOf of internal/ticket/ticket.go: a search by dedup_key defaults to any.
	status := str(a, "status")
	if status == "" && str(a, "dedup_key") != "" {
		status = "any"
	}
	var found []map[string]any
	tickets := append([]*srvTicket(nil), s.tickets...)
	sort.SliceStable(tickets, func(i, j int) bool { return tickets[i].createdAt < tickets[j].createdAt })
	for _, t := range tickets {
		if s.searchBlind || (str(a, "dedup_key") != "" && t.key != str(a, "dedup_key")) {
			continue
		}
		if st := status; (st == "" || st == "open") && t.closed || st == "closed" && !t.closed {
			continue
		}
		if q := str(a, "queue"); q != "" && t.queue != q {
			continue
		}
		found = append(found, map[string]any{"ticket_id": t.id, "title": t.title, "closed": t.closed,
			"created_at": t.createdAt})
	}
	return map[string]any{"tickets": found, "count": len(found)}, nil
}

func result(v any) intake.Call {
	b, _ := json.Marshal(v)
	return intake.Call{JSON: b}
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

const (
	jiraProject = "SEC"
	snGroup     = "0123456789abcdef0123456789abcdef"
)

func queueFor(connector string) string {
	if connector == "jira" {
		return jiraProject
	}
	return ""
}

func TestTheTicketLifecycleThroughTheContract(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	src := &fakeSource{items: []Item{finding("open")}}
	m := newTicketMirror(t, srv, src, jiraProject)

	pass(t, m)
	if len(srv.tickets) != 1 {
		t.Fatalf("%d tickets, want 1", len(srv.tickets))
	}
	tk := srv.tickets[0]
	if tk.key != "gibson:finding:f-1" || tk.queue != jiraProject || tk.priority != "high" {
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

// TestNoCallSendsALabel: ServiceNow refuses a label on a create and on a search. The
// adapter finds the ticket by its dedup key and sends no label at all.
func TestNoCallSendsALabel(t *testing.T) {
	for _, c := range []string{"jira", "servicenow"} {
		srv := &ticketServer{connectors: []string{c}}
		src := &fakeSource{items: []Item{finding("open")}}
		m := newTicketMirror(t, srv, src, queueFor(c))
		pass(t, m)
		src.items = []Item{finding("fixing")}
		pass(t, m)
		src.items = []Item{finding("verified")}
		pass(t, m)
		if len(srv.tickets) != 1 || !srv.tickets[0].closed {
			t.Fatalf("%s: tickets %d", c, len(srv.tickets))
		}
		for i, a := range srv.args {
			if _, ok := a["labels"]; ok {
				t.Errorf("%s call %d (%s) sends labels", c, i, srv.calls[i])
			}
			if _, ok := a["label"]; ok {
				t.Errorf("%s call %d (%s) sends a label filter", c, i, srv.calls[i])
			}
		}
		if srv.args[0]["dedup_key"] != "gibson:finding:f-1" {
			t.Errorf("%s: the first search is %v", c, srv.args[0])
		}
	}
}

func TestServiceNowTakesAnAssignmentGroupAsTheQueue(t *testing.T) {
	srv := &ticketServer{connectors: []string{"servicenow"}}
	pass(t, newTicketMirror(t, srv, &fakeSource{items: []Item{finding("open")}}, snGroup))
	if len(srv.tickets) != 1 || srv.tickets[0].queue != snGroup {
		t.Fatalf("%+v", srv.tickets)
	}
}

func TestARestartOpensNoSecondTicket(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	src := &fakeSource{items: []Item{finding("open")}}
	pass(t, newTicketMirror(t, srv, src, jiraProject))
	pass(t, newTicketMirror(t, srv, src, jiraProject)) // a new process has no memory
	if len(srv.tickets) != 1 {
		t.Fatalf("%d tickets, want 1", len(srv.tickets))
	}
}

func TestATimeoutAfterTheCreateOpensNoSecondTicket(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}, failAfterCreate: true}
	src := &fakeSource{items: []Item{finding("open")}}
	m := newTicketMirror(t, srv, src, jiraProject)
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

func TestAnIncidentGetsATicketToo(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	inc := Item{Kind: KindIncident, ID: "i-1", Title: "Phishing", Severity: "critical", Status: "open"}
	src := &fakeSource{items: []Item{inc}}
	m := newTicketMirror(t, srv, src, jiraProject)
	pass(t, m)
	inc.Status = "resolved"
	src.items = []Item{inc}
	pass(t, m)
	if tk := srv.tickets[0]; tk.priority != "critical" || !tk.closed || tk.key != "gibson:incident:i-1" {
		t.Fatalf("%+v", *tk)
	}
}

func TestAFindingAndAnIncidentWithOneIDGetTwoTickets(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	inc := Item{Kind: KindIncident, ID: "f-1", Title: "Phishing", Severity: "high", Status: "open"}
	pass(t, newTicketMirror(t, srv, &fakeSource{items: []Item{finding("open"), inc}}, jiraProject))
	if len(srv.tickets) != 2 {
		t.Fatalf("%d tickets, want 2: the kind is in the dedup key", len(srv.tickets))
	}
}

func TestAClosedTicketOfAnItemThatOpensAgainIsAnErrorAndNotANewTicket(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	src := &fakeSource{items: []Item{finding("open")}}
	m := newTicketMirror(t, srv, src, jiraProject)
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
	// "gibson:finding:" has 15 bytes, so an id can have 85.
	for _, id := range []string{"has space", "has/slash", strings.Repeat("a", 86), ""} {
		it := finding("open")
		it.ID = id
		m := newTicketMirror(t, srv, &fakeSource{items: []Item{it}}, jiraProject)
		if _, err := m.Pass(context.Background()); err == nil {
			t.Errorf("id %q: want an error", id)
		}
	}
	for _, c := range srv.calls {
		if c != "jira/search_tickets" && c != "jira/create_ticket" {
			continue
		}
		t.Fatalf("calls %v, want none", srv.calls)
	}
	it := finding("open")
	it.ID = strings.Repeat("a", 85)
	pass(t, newTicketMirror(t, srv, &fakeSource{items: []Item{it}}, jiraProject))
}

// TestAStatusThatTheTitleCannotHoldMakesNoWrite: the tag of the title is
// "[status] ". A status with another character would break it.
func TestAStatusThatTheTitleCannotHoldMakesNoWrite(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	src := &fakeSource{items: []Item{finding("open")}}
	m := newTicketMirror(t, srv, src, jiraProject)
	pass(t, m)
	n := len(srv.calls)
	for _, st := range []string{"Fixing", "fix ing", "fixing]", "", "fixing\n"} {
		src.items = []Item{finding(st)}
		if _, err := m.Pass(context.Background()); err == nil {
			t.Errorf("status %q: want an error", st)
		}
	}
	for _, c := range srv.calls[n:] {
		if c != "jira/search_tickets" {
			t.Fatalf("the adapter wrote %s with a bad status", c)
		}
	}
	bad := finding("Open!")
	bad.ID = "f-2"
	m2 := newTicketMirror(t, srv, &fakeSource{items: []Item{bad}}, jiraProject)
	if _, err := m2.Pass(context.Background()); err == nil {
		t.Fatal("a create with a bad status must fail")
	}
	if len(srv.tickets) != 1 {
		t.Fatalf("%d tickets, want 1", len(srv.tickets))
	}
}

// TestTwoTicketsWithOneKeyGiveTheOldestAndALog: the adapter takes the oldest ticket
// and logs the duplicate.
func TestTwoTicketsWithOneKeyGiveTheOldestAndALog(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	key := "gibson:finding:f-1"
	srv.tickets = []*srvTicket{
		{id: "T-new", key: key, queue: jiraProject, title: "[open] x", createdAt: "2026-11-21T12:00:00Z"},
		{id: "T-old", key: key, queue: jiraProject, title: "[fixing] x", createdAt: "2026-11-20T09:00:00Z"},
		{id: "T-mid", key: key, queue: jiraProject, title: "[open] x", createdAt: "2026-11-21T01:00:00Z"},
	}
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(old)
	tk, found, err := NewTicketAdapter("jira", jiraProject).Find(context.Background(), srv, finding("fixing"))
	if err != nil || !found || tk.Ref != "T-old" || tk.Status != "fixing" {
		t.Fatalf("ticket %+v, found %v, err %v", tk, found, err)
	}
	if !strings.Contains(logs.String(), "more than one ticket") || !strings.Contains(logs.String(), "T-old") {
		t.Fatalf("no log of the duplicate: %q", logs.String())
	}
}

func TestAJiraConnectorWithNoQueueDisablesTheMirrorWithOneLog(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	m, err := New(srv, &fakeSource{items: []Item{finding("open")}}, Adapters(""), log)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		sum, err := m.Pass(context.Background())
		if err != nil || !sum.Disabled {
			t.Fatalf("summary %+v, err %v", sum, err)
		}
	}
	if len(srv.calls) != 0 {
		t.Fatalf("calls %v, want none", srv.calls)
	}
	if n := strings.Count(logs.String(), "INTAKE_TICKET_QUEUE"); n != 1 {
		t.Fatalf("the cause was logged %d times, want 1:\n%s", n, logs.String())
	}
}

func TestAQueueThatTheServerRefusesDisablesTheMirror(t *testing.T) {
	for c, q := range map[string]string{"jira": "sec", "servicenow": "not-hex"} {
		srv := &ticketServer{connectors: []string{c}}
		m := newTicketMirror(t, srv, &fakeSource{items: []Item{finding("open")}}, q)
		if sum, err := m.Pass(context.Background()); err != nil || !sum.Disabled || len(srv.calls) != 0 {
			t.Fatalf("%s: summary %+v, err %v, calls %v", c, sum, err, srv.calls)
		}
	}
}

// TestAServiceNowTenantNeedsNoQueue: only Jira needs one.
func TestAServiceNowTenantNeedsNoQueue(t *testing.T) {
	srv := &ticketServer{connectors: []string{"servicenow"}}
	sum := pass(t, newTicketMirror(t, srv, &fakeSource{items: []Item{finding("open")}}, ""))
	if sum.Disabled || len(srv.tickets) != 1 {
		t.Fatalf("summary %+v, tickets %d", sum, len(srv.tickets))
	}
}

// TestTextIsCutByBytesAtACharacterAndHasNoControlCharacter: the servers count bytes,
// refuse a control character in a title, and refuse invalid UTF-8.
func TestTextIsCutByBytesAtACharacterAndHasNoControlCharacter(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}}
	it := finding("open")
	it.Title = strings.Repeat("é", 400) + "\x00\x1b[31m\u0085" // 2 and 1 byte characters, control characters
	it.Severity = "high\x07"
	it.URL = "https://console.example/f?q=\x01" + strings.Repeat("日", 20000)
	pass(t, newTicketMirror(t, srv, &fakeSource{items: []Item{it}}, jiraProject))
	if len(srv.tickets) != 1 {
		t.Fatalf("%d tickets: the server refused the call", len(srv.tickets))
	}
	tk := srv.tickets[0]
	if len(tk.title) > 255 || !utf8.ValidString(tk.title) {
		t.Fatalf("title %d bytes", len(tk.title))
	}
	if len(tk.description) > 32000 || !utf8.ValidString(tk.description) {
		t.Fatalf("title %d bytes, description %d bytes", len(tk.title), len(tk.description))
	}
	// Three bytes characters cut in the description: no half character.
	if strings.ContainsRune(tk.description, utf8.RuneError) {
		t.Fatal("the description has a cut character")
	}
	// A title of three byte characters is cut at a character too.
	it2 := finding("open")
	it2.ID = "f-2"
	it2.Title = strings.Repeat("日", 200)
	pass(t, newTicketMirror(t, srv, &fakeSource{items: []Item{it2}}, jiraProject))
	if len(srv.tickets) != 2 || len(srv.tickets[1].title) > 255 || !utf8.ValidString(srv.tickets[1].title) {
		t.Fatalf("tickets %d", len(srv.tickets))
	}
}

func TestAnInvalidUTF8TitleIsMadeValid(t *testing.T) {
	it := finding("open")
	it.Title = "bad \xff\xfe bytes"
	if got := title(it); !utf8.ValidString(got) {
		t.Fatalf("title %q is not valid UTF-8", got)
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
	long.Title = "a\n  b\tc"
	if got := title(long); got != "[open] a b c" {
		t.Fatalf("title = %q", got)
	}
}

func TestAGrantRefusalKeepsItsChainThroughTheAdapter(t *testing.T) {
	srv := &ticketServer{connectors: []string{"jira"}, grantErr: fmt.Errorf("daemon: %w", intake.ErrGrant)}
	m := newTicketMirror(t, srv, &fakeSource{items: []Item{finding("open")}}, jiraProject)
	if _, err := m.Pass(context.Background()); !errors.Is(err, intake.ErrGrant) {
		t.Fatalf("err = %v", err)
	}
}

func TestOldestTakesTheEarliestTimeWhateverTheOrder(t *testing.T) {
	got := oldest([]ticketResult{
		{TicketID: "b", CreatedAt: "2026-11-21T12:00:00Z"},
		{TicketID: "a", CreatedAt: "2026-11-20T09:00:00Z"},
		{TicketID: "c", CreatedAt: "bad time"},
	})
	if got.TicketID != "a" {
		t.Fatalf("got %s, want a", got.TicketID)
	}
}
