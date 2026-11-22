// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mirror

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode"
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

// Limits of the servers, in bytes. Source: internal/ticket/ticket.go and
// internal/kit/validate.go of zeroroot-ai/connectors.
const (
	maxTitle       = 255
	maxDescription = 32000
	maxDedupKey    = 100
	statusAny      = "any"
	// maxMatches is the number of tickets that a search asks for. One ticket is
	// expected. A second one is a duplicate, and the adapter logs it.
	maxMatches = 5
)

// The dedup key is "gibson:<kind>:<id>". ServiceNow has no labels, so the key is
// the one handle that both servers keep: a label on Jira, correlation_id on
// ServiceNow. The contract filter dedup_key of search_tickets finds it.
//
// CONTRACT NOTE: search_tickets with a dedup_key filter is in the contract that
// the connectors lane adds. It is not in connectors v0.3.0. Until that release
// ships, a server refuses the filter, and Find fails with its message.
const keyPrefix = "gibson:"

// dedupFormat is the format of a dedup key. Source: internal/ticket/ticket.go.
var dedupFormat = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@=+-]*$`)

// idFormat is what an item id may hold. It keeps the dedup key in dedupFormat.
var idFormat = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// statusFormat is a status that the title tag can hold.
var statusFormat = regexp.MustCompile(`^[a-z_]+$`)

// The queue formats. Sources: jira/server.go (projectKey) and the checkID call in
// servicenow/server.go (kit.Hex32) of zeroroot-ai/connectors.
var (
	jiraQueue = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,9}$`)
	snQueue   = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
)

// statusTag is the first part of the title of a ticket. It holds the status that
// the mirror wrote last, for example "[fixing] Open port". The contract has no
// call to change a label, so the title is the one field that update_ticket can
// change and that search_tickets returns.
var statusTag = regexp.MustCompile(`^\[([a-z_]+)\] `)

// TicketAdapter writes tickets through a ticket server of the connectors repo.
// It keeps no state. The ticket holds the dedup key of the item and the last
// status (the start of the title).
type TicketAdapter struct {
	connector string
	queue     string
}

var _ Adapter = (*TicketAdapter)(nil)

// NewTicketAdapter returns the adapter of one ticket connector. queue is the
// project key on Jira, and it is required there. On ServiceNow it is the id of the
// assignment group, and it is optional.
func NewTicketAdapter(connector, queue string) *TicketAdapter {
	return &TicketAdapter{connector: connector, queue: queue}
}

// Connector is the catalog id of the connector.
func (a *TicketAdapter) Connector() string { return a.connector }

// Ready refuses a queue that the server would refuse. Jira refuses a create with
// no project key, so INTAKE_TICKET_QUEUE is required for it.
func (a *TicketAdapter) Ready() error {
	switch a.connector {
	case "jira":
		if a.queue == "" {
			return errors.New("INTAKE_TICKET_QUEUE is not set, and Jira needs the key of a project, for example SEC")
		}
		if !jiraQueue.MatchString(a.queue) {
			return fmt.Errorf("INTAKE_TICKET_QUEUE %q is not the key of a Jira project, for example SEC", a.queue)
		}
	case "servicenow":
		if a.queue != "" && !snQueue.MatchString(a.queue) {
			return fmt.Errorf("INTAKE_TICKET_QUEUE %q is not the 32 character id of an assignment group", a.queue)
		}
	}
	return nil
}

type ticketResult struct {
	TicketID  string `json:"ticket_id"`
	Title     string `json:"title"`
	Closed    bool   `json:"closed"`
	CreatedAt string `json:"created_at"`
}

// dedupKey is the key of the ticket of an item.
func dedupKey(it Item) (string, error) {
	key := keyPrefix + string(it.Kind) + ":" + it.ID
	if !idFormat.MatchString(it.ID) || len(key) > maxDedupKey || !dedupFormat.MatchString(key) {
		return "", fmt.Errorf("the id %q of the %s cannot be part of a dedup key of the ticket contract", it.ID, it.Kind)
	}
	return key, nil
}

// checkStatus refuses a status that the title tag cannot hold, before any write.
func checkStatus(it Item) error {
	if !statusFormat.MatchString(it.Status) {
		return fmt.Errorf("the status %q of the %s is not a lower case word, so the title cannot hold it", it.Status, it.Kind)
	}
	return nil
}

// Find looks for the ticket of the item by its dedup key, in each status. When
// two tickets match, it takes the oldest and logs it.
func (a *TicketAdapter) Find(ctx context.Context, c intake.Caller, it Item) (Ticket, bool, error) {
	key, err := dedupKey(it)
	if err != nil {
		return Ticket{}, false, err
	}
	args := map[string]any{"dedup_key": key, "status": statusAny, "limit": maxMatches}
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
	t := oldest(res.Tickets)
	if len(res.Tickets) > 1 {
		slog.Warn("mirror: more than one ticket has the dedup key, so the mirror takes the oldest",
			"connector", a.connector, "dedup_key", key, "tickets", len(res.Tickets), "taken", t.TicketID)
	}
	status := ""
	if m := statusTag.FindStringSubmatch(t.Title); m != nil {
		status = m[1]
	}
	return Ticket{Ref: t.TicketID, Status: status, Closed: t.Closed}, true, nil
}

// oldest returns the ticket with the earliest created_at. A ticket with no time
// that parses comes after the others, and the first one in the list breaks a tie.
func oldest(ts []ticketResult) ticketResult {
	best := 0
	var bestAt time.Time
	have := false
	for i, t := range ts {
		at, err := time.Parse(time.RFC3339, t.CreatedAt)
		switch {
		case err != nil:
		case !have || at.Before(bestAt):
			best, bestAt, have = i, at, true
		}
	}
	return ts[best]
}

// Open creates the ticket. The dedup key makes a repeat of this call, for
// example after a timeout, return the first ticket and make no second one. The
// call has no labels, because ServiceNow refuses them.
func (a *TicketAdapter) Open(ctx context.Context, c intake.Caller, it Item) (Ticket, error) {
	key, err := dedupKey(it)
	if err != nil {
		return Ticket{}, err
	}
	if err := checkStatus(it); err != nil {
		return Ticket{}, err
	}
	args := map[string]any{
		"title":       title(it),
		"description": description(it),
		"priority":    priority(it.Severity),
		"dedup_key":   key,
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
	if err := checkStatus(it); err != nil {
		return err
	}
	body := fmt.Sprintf("Gibson status of the %s: %s.", it.Kind, it.Status)
	if it.URL != "" {
		body += " " + text(it.URL, 2000)
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
	res := fmt.Sprintf("Gibson set the %s to %s.", it.Kind, text(it.Status, 100))
	if it.URL != "" {
		res += " " + text(it.URL, 2000)
	}
	args := map[string]any{"ticket_id": t.Ref, "resolution": res}
	if err := intake.CallInto(ctx, c, a.connector, toolClose, args, nil); err != nil {
		return fmt.Errorf("close the ticket: %w", err)
	}
	return nil
}

// title is "[status] title", at most 255 bytes, with no control character.
func title(it Item) string {
	return clipBytes(line("["+it.Status+"] "+it.Title), maxTitle)
}

func description(it Item) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\nSeverity: %s\nStatus: %s\n", it.Kind, line(it.Title), line(it.Severity), line(it.Status))
	if it.URL != "" {
		fmt.Fprintf(&b, "Link: %s\n", line(it.URL))
	}
	fmt.Fprintf(&b, "Gibson id: %s\nGibson is the source. A change of this ticket changes nothing in Gibson.", line(it.ID))
	return clipBytes(text(b.String(), maxDescription*2), maxDescription)
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

// line makes a text of one line. It turns each control character and each space
// into one space, and it makes the text valid UTF-8. The servers refuse a
// control character in a title.
func line(s string) string {
	s = strings.ToValidUTF8(s, "?")
	blank := func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }
	return strings.Join(strings.FieldsFunc(s, blank), " ")
}

// text keeps new lines and tabs, as a description allows, and drops each other
// control character. It cuts the text to at most n bytes.
func text(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
	return clipBytes(s, n)
}

// clipBytes cuts s to at most n bytes, at the start of a character.
func clipBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
