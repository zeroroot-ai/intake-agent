// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pager

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
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

// Limits of the server: summary 1024 characters, dedup_key 255.
const (
	maxSummary  = 1024
	maxDedupKey = 255
)

// PagerDutyAdapter pages through the paging connector pagerduty. It keeps no
// state. The dedup key of the alert is the key of the wait, so PagerDuty groups
// each repeat of a trigger into one alert, and find_incidents shows that it
// exists.
type PagerDutyAdapter struct{}

var _ Adapter = PagerDutyAdapter{}

// NewPagerDutyAdapter returns the adapter.
func NewPagerDutyAdapter() PagerDutyAdapter { return PagerDutyAdapter{} }

// Connector is the catalog id of the connector.
func (PagerDutyAdapter) Connector() string { return "pagerduty" }

// Paged reports whether an incident exists for the key. find_incidents returns
// the incidents of every status, so a page that was already answered counts too.
func (PagerDutyAdapter) Paged(ctx context.Context, c intake.Caller, key string) (bool, error) {
	if len(key) > maxDedupKey {
		return false, fmt.Errorf("the key %q is longer than %d characters", key, maxDedupKey)
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
func (PagerDutyAdapter) Page(ctx context.Context, c intake.Caller, w Waiting, key string) error {
	if len(key) > maxDedupKey {
		return fmt.Errorf("the key %q is longer than %d characters", key, maxDedupKey)
	}
	summary := fmt.Sprintf("Gibson: %s of %s waits on a person for %s", w.Kind, w.ID, w.Waited.Round(time.Minute))
	details := map[string]string{
		"kind":   w.Kind,
		"id":     w.ID,
		"since":  w.Since.UTC().Format(time.RFC3339),
		"waited": w.Waited.Round(time.Second).String(),
	}
	if w.URL != "" {
		details["link"] = w.URL
	}
	args := map[string]any{
		"summary":        clip(summary, maxSummary),
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

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
