// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pager

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zeroroot-ai/intake-agent/internal/intake"
)

// The tools of the pagerduty server of zeroroot-ai/connectors. Source:
// https://github.com/zeroroot-ai/connectors/blob/main/pagerduty/README.md. The
// server sends an alert through the Events API v2 and reads incidents through the
// REST API v2.
const (
	toolTrigger = "trigger_alert"
	toolFind    = "find_incidents"
)

// Limits of the server, in bytes. Source: pagerduty/server.go of
// zeroroot-ai/connectors (maxSummary, maxDedup, maxDetails, maxDetail,
// dedupFormat) and CheckString of internal/kit/validate.go.
const (
	maxSummary = 1024
	maxDedup   = 255
	maxDetails = 20
	maxDetail  = 500
)

// dedupFormat is the format of a dedup key of the server.
var dedupFormat = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@=+-]*$`)

// OnCall pages through the paging connector pagerduty. It keeps no
// state. The dedup key of the alert is the key of the wait, so PagerDuty groups
// each repeat of a trigger into one alert, and find_incidents shows that it
// exists.
type OnCall struct{}

var _ Adapter = OnCall{}

// NewOnCall returns the adapter.
func NewOnCall() OnCall { return OnCall{} }

// Connector is the catalog id of the connector.
func (OnCall) Connector() string { return "pagerduty" }

// checkKey refuses a key that the server refuses, before any call.
func checkKey(key string) error {
	if len(key) > maxDedup || !dedupFormat.MatchString(key) {
		return fmt.Errorf("the key %q is not a dedup key of the server: at most %d bytes of A-Z a-z 0-9 . _ : / @ = + -",
			key, maxDedup)
	}
	return nil
}

// Paged reports whether an incident exists for the key. find_incidents returns
// the incidents of every status, so a page that was already answered counts too.
func (OnCall) Paged(ctx context.Context, c intake.Caller, key string) (bool, error) {
	if err := checkKey(key); err != nil {
		return false, err
	}
	var res struct {
		Count     int               `json:"count"`
		Incidents []json.RawMessage `json:"incidents"`
	}
	if err := intake.CallInto(ctx, c, "pagerduty", toolFind, map[string]any{"dedup_key": key}, &res); err != nil {
		return false, fmt.Errorf("find the incident of the page: %w", err)
	}
	return res.Count > 0 || len(res.Incidents) > 0, nil
}

// Page triggers an alert. The call is safe to repeat: PagerDuty groups a repeat
// with the same dedup_key into the alert that is open.
func (OnCall) Page(ctx context.Context, c intake.Caller, w Waiting, key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	summary := fmt.Sprintf("Gibson: %s of %s waits on a person for %s", w.Kind, w.ID, w.Waited.Round(time.Minute))
	// The server refuses an empty value and a control character, so each value is
	// cut to the limit in bytes, and an empty one is left out.
	details := map[string]string{}
	for k, v := range map[string]string{
		"kind":   w.Kind,
		"id":     w.ID,
		"since":  w.Since.UTC().Format(time.RFC3339),
		"waited": w.Waited.Round(time.Second).String(),
		"link":   w.URL,
	} {
		if v = clipBytes(line(v), maxDetail); v != "" {
			details[k] = v
		}
	}
	args := map[string]any{
		"summary":        clipBytes(line(summary), maxSummary),
		"source":         "gibson",
		"dedup_key":      key,
		"severity":       "error",
		"custom_details": details,
	}
	if err := intake.CallInto(ctx, c, "pagerduty", toolTrigger, args, nil); err != nil {
		return fmt.Errorf("trigger the alert: %w", err)
	}
	return nil
}

// line makes a text of one line. Each control character and each space becomes
// one space, and the text is valid UTF-8. The server refuses a control character.
func line(s string) string {
	s = strings.ToValidUTF8(s, "?")
	blank := func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }
	return strings.Join(strings.FieldsFunc(s, blank), " ")
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
