// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/intake-agent/internal/intake"
)

// pdServer is a mock of the pagerduty server of the connectors repo. It follows
// the README of that server: trigger_alert needs summary, source and dedup_key,
// PagerDuty groups the events of one dedup_key into one incident, and
// find_incidents returns the incidents of a dedup_key in every status.
type pdServer struct {
	incidents map[string]*pdIncident
	order     []string
	events    int
	// failAfterTrigger makes trigger_alert send the event and then fail, as a
	// timeout after PagerDuty took the event does.
	failAfterTrigger bool
	// findBlind makes find_incidents find nothing, as PagerDuty does for a moment
	// after an event.
	findBlind bool
	grantErr  error
}

type pdIncident struct {
	summary string
	details map[string]any
	status  string
}

func newPD() *pdServer { return &pdServer{incidents: map[string]*pdIncident{}} }

func (s *pdServer) Tools(context.Context) ([]intake.Tool, error) {
	return []intake.Tool{{Connector: "pagerduty", Name: "trigger_alert"}}, nil
}

func (s *pdServer) Invoke(_ context.Context, connector, tool string, a map[string]any) (intake.Call, error) {
	if s.grantErr != nil {
		return intake.Call{}, s.grantErr
	}
	if connector != "pagerduty" {
		return intake.Call{}, fmt.Errorf("no connector %q", connector)
	}
	key, _ := a["dedup_key"].(string)
	if key == "" || len(key) > 255 {
		return intake.Call{}, errors.New("dedup_key is required, at most 255 characters")
	}
	switch tool {
	case "trigger_alert":
		sum, _ := a["summary"].(string)
		src, _ := a["source"].(string)
		if sum == "" || len(sum) > 1024 || src == "" {
			return intake.Call{}, errors.New("trigger_alert: bad summary or source")
		}
		switch sev, _ := a["severity"].(string); sev {
		case "", "critical", "error", "warning", "info":
		default:
			return intake.Call{}, errors.New("trigger_alert: bad severity")
		}
		details, _ := a["custom_details"].(map[string]string)
		if len(details) > 20 {
			return intake.Call{}, errors.New("trigger_alert: too many details")
		}
		s.events++
		if _, ok := s.incidents[key]; !ok {
			d := map[string]any{}
			for k, v := range details {
				d[k] = v
			}
			s.incidents[key] = &pdIncident{summary: sum, details: d, status: "triggered"}
			s.order = append(s.order, key)
		}
		if s.failAfterTrigger {
			s.failAfterTrigger = false
			return intake.Call{}, errors.New("trigger_alert: timeout")
		}
		return res(map[string]any{"dedup_key": key, "action": "trigger", "message": "Event processed"}), nil
	case "find_incidents":
		var list []map[string]any
		if inc, ok := s.incidents[key]; ok && !s.findBlind {
			list = append(list, map[string]any{"incident_id": "PT1", "status": inc.status, "dedup_key": key})
		}
		return res(map[string]any{"incidents": list, "count": len(list)}), nil
	}
	return intake.Call{}, fmt.Errorf("no tool %q", tool)
}

func res(v any) intake.Call { b, _ := json.Marshal(v); return intake.Call{JSON: b} }

func newPDPager(t *testing.T, s *pdServer, src *fakeSource) *Pager {
	t.Helper()
	p, err := New(s, src, Adapters(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func passOK(t *testing.T, p *Pager) {
	t.Helper()
	if _, err := p.Pass(context.Background()); err != nil {
		t.Fatalf("pass: %v", err)
	}
}

func TestAWaitOverTheLimitGivesOneAlertWithALink(t *testing.T) {
	srv := newPD()
	src := &fakeSource{items: []Waiting{wait("f-1", 5*time.Hour)}}
	p := newPDPager(t, srv, src)
	for range 3 {
		passOK(t, p)
	}
	if len(srv.incidents) != 1 || srv.events != 1 {
		t.Fatalf("incidents %d, events %d, want 1 and 1", len(srv.incidents), srv.events)
	}
	inc := srv.incidents[Key(src.items[0])]
	if inc == nil {
		t.Fatalf("the dedup key is not the wait key: %v", srv.order)
	}
	if inc.details["link"] != "https://console.example/findings/f-1" || inc.details["id"] != "f-1" ||
		!strings.Contains(inc.summary, "merge_refused") {
		t.Fatalf("%+v", *inc)
	}
}

func TestARestartPagesNoSecondTime(t *testing.T) {
	srv := newPD()
	src := &fakeSource{items: []Waiting{wait("f-1", 5*time.Hour)}}
	passOK(t, newPDPager(t, srv, src))
	passOK(t, newPDPager(t, srv, src))
	if srv.events != 1 {
		t.Fatalf("%d events, want 1", srv.events)
	}
}

func TestAResolvedIncidentStillCountsAsPaged(t *testing.T) {
	srv := newPD()
	src := &fakeSource{items: []Waiting{wait("f-1", 5*time.Hour)}}
	passOK(t, newPDPager(t, srv, src))
	srv.incidents[Key(src.items[0])].status = "resolved"
	passOK(t, newPDPager(t, srv, src))
	if srv.events != 1 {
		t.Fatalf("%d events, want 1", srv.events)
	}
}

func TestATimeoutAfterTheTriggerMakesOneIncident(t *testing.T) {
	srv := newPD()
	srv.failAfterTrigger = true
	src := &fakeSource{items: []Waiting{wait("f-1", 5*time.Hour)}}
	p := newPDPager(t, srv, src)
	if _, err := p.Pass(context.Background()); err == nil {
		t.Fatal("want the timeout")
	}
	// The next pass finds the incident and sends nothing.
	passOK(t, p)
	if len(srv.incidents) != 1 || srv.events != 1 {
		t.Fatalf("incidents %d, events %d, want 1 and 1", len(srv.incidents), srv.events)
	}
}

// TestTheDedupKeyHoldsWhenFindDoesNotSeeTheIncidentYet: PagerDuty can need a moment
// to make the incident. A new process repeats the trigger. PagerDuty groups it
// into the same incident, so there is still one.
func TestTheDedupKeyHoldsWhenFindDoesNotSeeTheIncidentYet(t *testing.T) {
	srv := newPD()
	src := &fakeSource{items: []Waiting{wait("f-1", 5*time.Hour)}}
	passOK(t, newPDPager(t, srv, src))
	srv.findBlind = true
	passOK(t, newPDPager(t, srv, src))
	if len(srv.incidents) != 1 {
		t.Fatalf("%d incidents, want 1", len(srv.incidents))
	}
}

func TestAKeyOverTheLimitMakesNoCall(t *testing.T) {
	srv := newPD()
	long := wait(strings.Repeat("a", 300), 5*time.Hour)
	p := newPDPager(t, srv, &fakeSource{items: []Waiting{long}})
	if _, err := p.Pass(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	if srv.events != 0 {
		t.Fatal("a call was made with a key that the server refuses")
	}
}

func TestAGrantRefusalKeepsItsChainThroughThePagerDutyAdapter(t *testing.T) {
	srv := newPD()
	srv.grantErr = fmt.Errorf("daemon: %w", intake.ErrGrant)
	p := newPDPager(t, srv, &fakeSource{items: []Waiting{wait("f-1", 5*time.Hour)}})
	if _, err := p.Pass(context.Background()); !errors.Is(err, intake.ErrGrant) {
		t.Fatalf("err = %v", err)
	}
}

func TestSummaryIsCutToTheLimit(t *testing.T) {
	if got := clip(strings.Repeat("é ", 2000), maxSummary); len([]rune(got)) != maxSummary {
		t.Fatalf("%d characters", len([]rune(got)))
	}
}
