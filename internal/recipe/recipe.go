// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package recipe holds the read recipes of the intake agent.
//
// One recipe states how to read one connector: which tool to call, which
// arguments to send, how to turn the result into items, and which field of an
// item is the cursor. The recipes are the rule table of this agent. A recipe
// lives in its own file, named after the catalog id of its connector.
//
// A recipe is only valid with a vendor source. A tool name or a result shape
// that nobody verified in a vendor document has no recipe (see README.md).
package recipe

import (
	"errors"
	"fmt"
	"strings"
)

// Class is the tool class of a connector (ADR-0177).
type Class string

// The classes in scope for intake.
const (
	SIEM     Class = "siem"
	EDR      Class = "edr"
	Scanner  Class = "scanner"
	Identity Class = "identity"
	Cloud    Class = "cloud"
)

// InScope reports whether intake reads a connector of this class.
func (c Class) InScope() bool {
	switch c {
	case SIEM, EDR, Scanner, Identity, Cloud:
		return true
	default:
		return false
	}
}

// IsFlaw reports whether a result of this class is a flaw. A flaw has a fix and
// becomes a finding. Any other in-scope class gives an alert, which becomes an
// Alert node and never a finding.
func (c Class) IsFlaw() bool { return c == Scanner || c == Cloud }

// Item is one result of a tool, in the shape the agent hands to the daemon.
type Item struct {
	// ID is the id that the tool gives the result. It is the identity of the
	// result, so a second read of the result gives the same ID.
	ID string
	// Cursor orders the items of one connector. It sorts as a string, so a
	// recipe gives a value that sorts in time order, such as an RFC 3339 time.
	Cursor      string
	Title       string
	Description string
	// Severity is one of critical, high, medium, low or info. Empty means info.
	Severity string
}

// Marker is the position of the agent in one connector.
type Marker struct {
	// Cursor is the greatest cursor that the agent handed to the daemon.
	Cursor string `json:"cursor"`
	// AtCursor lists the ids of the items at exactly that cursor. Two items
	// can share a cursor, so the agent must not skip the second one.
	AtCursor []string `json:"at_cursor,omitempty"`
}

// Recipe is the read recipe of one connector.
type Recipe struct {
	// Connector is the catalog id of the connector, such as "wiz".
	Connector string
	Class     Class
	// Source is the URL of the vendor document that names the tool and its
	// arguments. It is required.
	Source string
	// Tool is the name of the read tool on the MCP server of the connector.
	Tool string
	// Args builds the arguments of one call from the marker of the connector.
	Args func(m Marker) map[string]any
	// Parse turns the JSON result of the tool into items.
	Parse func(result []byte) ([]Item, error)
}

// Validate reports why a recipe cannot be used.
func (r Recipe) Validate() error {
	var errs []error
	if strings.TrimSpace(r.Connector) == "" {
		errs = append(errs, errors.New("no connector"))
	}
	if !r.Class.InScope() {
		errs = append(errs, fmt.Errorf("class %q is not in scope", r.Class))
	}
	if !strings.HasPrefix(r.Source, "https://") {
		errs = append(errs, errors.New("source must be the https URL of a vendor document"))
	}
	if strings.TrimSpace(r.Tool) == "" {
		errs = append(errs, errors.New("no tool"))
	}
	if r.Args == nil {
		errs = append(errs, errors.New("no Args"))
	}
	if r.Parse == nil {
		errs = append(errs, errors.New("no Parse"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("recipe %q: %w", r.Connector, err)
	}
	return nil
}

// Book is a set of valid recipes, one for each connector.
type Book struct {
	byConnector map[string]Recipe
}

// NewBook checks each recipe and refuses two recipes for one connector.
func NewBook(rs ...Recipe) (*Book, error) {
	b := &Book{byConnector: make(map[string]Recipe, len(rs))}
	for _, r := range rs {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		if _, dup := b.byConnector[r.Connector]; dup {
			return nil, fmt.Errorf("recipe %q: declared twice", r.Connector)
		}
		b.byConnector[r.Connector] = r
	}
	return b, nil
}

// For returns the recipe of a connector.
func (b *Book) For(connector string) (Recipe, bool) {
	r, ok := b.byConnector[connector]
	return r, ok
}
