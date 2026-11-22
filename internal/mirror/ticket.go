// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mirror

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/zeroroot-ai/intake-agent/internal/intake"
)

// The tools of the ticket contract. Source: the section "Ticket contract" of
// https://github.com/zeroroot-ai/connectors/blob/main/README.md. The servers
// jira and servicenow have the same tool names, arguments and results.
const (
	toolCreate  = "create_ticket"
	toolUpdate  = "update_ticket"
	toolComment = "add_comment"
	toolClose   = "close_ticket"
	toolSearch  = "search_tickets"
)

// Limits of the contract.
const (
	maxTitle       = 255
	maxDescription = 32000
	maxDedupKey    = 100
	statusAny      = "any"
)

// labelPrefix starts the label that finds the ticket of an item. A label has at
// most 50 characters of A-Z a-z 0-9 . _ : -, so the id of an item has at most
// 50 - len(labelPrefix) of them.
const labelPrefix = "gibson:"

// idFormat is what an item id may hold. It is a subset of what the dedup key and
// the label of the contract accept, so one id serves as both.
var idFormat = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// statusTag is the first part of the title of a ticket. It holds the status that
// the mirror wrote last, for example "[fixing] Open port". The contract has no
// call to change a label, so the title is the one field that update_ticket can
// change and that search_tickets returns.
var statusTag = regexp.MustCompile(`^\[([a-z_]+)\] `)

// TicketAdapter writes tickets through a ticket server of the connectors repo.
// It keeps no state. The ticket holds the id of the item (the label and the
// dedup key) and the last status (the start of the title).
type TicketAdapter struct {
	connector string
	queue     string
}

var _ Adapter = (*TicketAdapter)(nil)

// NewTicketAdapter returns the adapter of one ticket connector. queue is the
// project key on Jira and the id of the assignment group on ServiceNow. It can be
// empty.
func NewTicketAdapter(connector, queue string) *TicketAdapter {
	return &TicketAdapter{connector: connector, queue: queue}
}

// Connector is the catalog id of the connector.
func (a *TicketAdapter) Connector() string { return a.connector }

type ticketResult struct {
	TicketID string `json:"ticket_id"`
	Title    string `json:"title"`
	Closed   bool   `json:"closed"`
}

func (a *TicketAdapter) checkID(it Item) error {
	if len(labelPrefix)+len(it.ID) > 50 || len(it.ID) > maxDedupKey || !idFormat.MatchString(it.ID) {
		return fmt.Errorf("the id %q of the %s cannot be a dedup key or a label of the ticket contract", it.ID, it.Kind)
	}
	return nil
}

// Find looks for the ticket of the item by its label, in each status.
func (a *TicketAdapter) Find(ctx context.Context, c intake.Caller, it Item) (Ticket, bool, error) {
	if err := a.checkID(it); err != nil {
		return Ticket{}, false, err
	}
	args := map[string]any{"label": labelPrefix + it.ID, "status": statusAny, "limit": 2}
	if a.queue != "" {
		args["queue"] = a.queue
	}
	var res struct {
		Tickets []ticketResult `json:"tickets"`
	}
	if err := intake.CallInto(ctx, c, a.connector, toolSearch, args, &res); err != nil {
		return Ticket{}, false, fmt.Errorf("search the ticket of the item: %w", err)
	}
	if len(res.Tickets) == 0 {
		return Ticket{}, false, nil
	}
	t := res.Tickets[0]
	status := ""
	if m := statusTag.FindStringSubmatch(t.Title); m != nil {
		status = m[1]
	}
	return Ticket{Ref: t.TicketID, Status: status, Closed: t.Closed}, true, nil
}

// Open creates the ticket. The dedup key is the id of the item, so a repeat of
// this call, for example after a timeout, returns the first ticket and makes no
// second one.
func (a *TicketAdapter) Open(ctx context.Context, c intake.Caller, it Item) (Ticket, error) {
	if err := a.checkID(it); err != nil {
		return Ticket{}, err
	}
	args := map[string]any{
		"title":       title(it),
		"description": description(it),
		"priority":    priority(it.Severity),
		"labels":      []string{labelPrefix + it.ID},
		"dedup_key":   it.ID,
	}
	if a.queue != "" {
		args["queue"] = a.queue
	}
	var res ticketResult
	if err := intake.CallInto(ctx, c, a.connector, toolCreate, args, &res); err != nil {
		return Ticket{}, fmt.Errorf("create the ticket: %w", err)
	}
	if res.TicketID == "" {
		return Ticket{}, errors.New("create the ticket: the result has no ticket_id")
	}
	return Ticket{Ref: res.TicketID, Status: it.Status}, nil
}

// Update writes the new status. It adds a comment first and then changes the
// title, because the title is the record of the last status. When the call fails
// between the two, the next pass tries both again, and no status change is lost.
// The contract has no call to reopen a closed ticket, so Update refuses one.
func (a *TicketAdapter) Update(ctx context.Context, c intake.Caller, t Ticket, it Item) error {
	if t.Closed {
		return fmt.Errorf("the ticket %s is closed, and the ticket contract has no call to reopen it", t.Ref)
	}
	body := fmt.Sprintf("Gibson status of the %s: %s.", it.Kind, it.Status)
	if it.URL != "" {
		body += " " + it.URL
	}
	if err := intake.CallInto(ctx, c, a.connector, toolComment,
		map[string]any{"ticket_id": t.Ref, "body": body}, nil); err != nil {
		return fmt.Errorf("comment the status: %w", err)
	}
	args := map[string]any{"ticket_id": t.Ref, "title": title(it), "priority": priority(it.Severity)}
	if err := intake.CallInto(ctx, c, a.connector, toolUpdate, args, nil); err != nil {
		return fmt.Errorf("write the status in the title: %w", err)
	}
	return nil
}

// Close closes the ticket with a resolution.
func (a *TicketAdapter) Close(ctx context.Context, c intake.Caller, t Ticket, it Item) error {
	res := fmt.Sprintf("Gibson set the %s to %s.", it.Kind, it.Status)
	if it.URL != "" {
		res += " " + it.URL
	}
	args := map[string]any{"ticket_id": t.Ref, "resolution": res}
	if err := intake.CallInto(ctx, c, a.connector, toolClose, args, nil); err != nil {
		return fmt.Errorf("close the ticket: %w", err)
	}
	return nil
}

// title is "[status] title", at most 255 characters.
func title(it Item) string {
	return clip("["+it.Status+"] "+oneLine(it.Title), maxTitle)
}

func description(it Item) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\nSeverity: %s\nStatus: %s\n", it.Kind, oneLine(it.Title), it.Severity, it.Status)
	if it.URL != "" {
		fmt.Fprintf(&b, "Link: %s\n", it.URL)
	}
	fmt.Fprintf(&b, "Gibson id: %s\nGibson is the source. A change of this ticket changes nothing in Gibson.", it.ID)
	return clip(b.String(), maxDescription)
}

// priority maps a severity of Gibson to a priority of the contract.
func priority(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "low", "info":
		return "low"
	default:
		return "medium"
	}
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// clip cuts s to at most n characters.
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}
