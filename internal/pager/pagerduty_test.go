// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

// The refusals below are copied from the pagerduty server of zeroroot-ai/connectors
// (pagerduty/server.go: dedupFormat, fieldFormat, maxSummary, maxDedup, maxDetails,
// maxDetail) and from CheckString of internal/kit/validate.go.
var (
	srvDedup = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@=+-]*$`)
	srvField = regexp.MustCompile(`^[A-Za-z0-9._ :/-]{1,100}$`)
)

// checkString is CheckString: not empty, at most limit bytes, valid UTF-8, no
// control character.
func checkString(field, v string, limit int) error {
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

func (s *pdServer) Invoke(_ context.Context, connector, tool string, a map[string]any) (intake.Call, error) {
	if s.grantErr != nil {
		return intake.Call{}, s.grantErr
	}
	if connector != "pagerduty" {
		return intake.Call{}, fmt.Errorf("no connector %q", connector)
	}
	key, _ := a["dedup_key"].(string)
	if err := checkString("dedup_key", key, 255); err != nil || !srvDedup.MatchString(key) {
		return intake.Call{}, errors.New("check dedup_key: the key has the wrong format")
	}
	switch tool {
	case "trigger_alert":
		return s.trigger(key, a)
	case "find_incidents":
		var list []map[string]any
		if inc, ok := s.incidents[key]; ok && !s.findBlind {
			list = append(list, map[string]any{"incident_id": "PT1", "status": inc.status, "dedup_key": key})
		}
		return res(map[string]any{"incidents": list, "count": len(list)}), nil
	}
	return intake.Call{}, fmt.Errorf("no tool %q", tool)
}

func (s *pdServer) trigger(key string, a map[string]any) (intake.Call, error) {
	sum, _ := a["summary"].(string)
	src, _ := a["source"].(string)
	if err := checkString("summary", sum, 1024); err != nil {
		return intake.Call{}, err
	}
	if err := checkString("source", src, 255); err != nil {
		return intake.Call{}, err
	}
	switch sev, _ := a["severity"].(string); sev {
	case "", "critical", "error", "warning", "info":
	default:
		return intake.Call{}, errors.New("trigger_alert: bad severity")
	}
	details, _ := a["custom_details"].(map[string]string)
	if len(details) > 20 {
		return intake.Call{}, errors.New("trigger_alert: custom_details has more than 20 pairs")
	}
	d := map[string]any{}
	for k, v := range details {
		if !srvField.MatchString(k) {
			return intake.Call{}, errors.New("a custom_details key has the wrong format")
		}
		if err := checkString("custom_details value", v, 500); err != nil {
			return intake.Call{}, err
		}
		d[k] = v
	}
	s.events++
	if _, ok := s.incidents[key]; !ok {
		s.incidents[key] = &pdIncident{summary: sum, details: d, status: "triggered"}
		s.order = append(s.order, key)
	}
	if s.failAfterTrigger {
		s.failAfterTrigger = false
		return intake.Call{}, errors.New("trigger_alert: timeout")
	}
	return res(map[string]any{"dedup_key": key, "action": "trigger", "message": "Event processed"}), nil
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

func TestAGrantRefusalKeepsItsChainThroughThePagerDuty(t *testing.T) {
	srv := newPD()
	srv.grantErr = fmt.Errorf("daemon: %w", intake.ErrGrant)
	p := newPDPager(t, srv, &fakeSource{items: []Waiting{wait("f-1", 5*time.Hour)}})
	if _, err := p.Pass(context.Background()); !errors.Is(err, intake.ErrGrant) {
		t.Fatalf("err = %v", err)
	}
}

// TestALongLinkAndControlCharactersDoNotMakeTheServerRefuseTheCall: the server counts
// bytes and refuses a control character. The adapter cuts at a character and strips.
func TestALongLinkAndControlCharactersDoNotMakeTheServerRefuseTheCall(t *testing.T) {
	srv := newPD()
	w := wait("f-1", 5*time.Hour)
	w.URL = "https://console.example/f?x=\x00\x1b" + strings.Repeat("日", 2000) // 6000 bytes
	p := newPDPager(t, srv, &fakeSource{items: []Waiting{w}})
	passOK(t, p)
	inc := srv.incidents[Key(w)]
	if inc == nil {
		t.Fatal("the server refused the call")
	}
	link, _ := inc.details["link"].(string)
	if len(link) > 500 || len(link) < 490 || !utf8.ValidString(link) || strings.ContainsAny(link, "\x00\x1b") {
		t.Fatalf("the link has %d bytes, valid = %v", len(link), utf8.ValidString(link))
	}
}

func TestAnEmptyLinkIsLeftOutOfTheDetails(t *testing.T) {
	srv := newPD()
	w := wait("f-1", 5*time.Hour)
	w.URL = ""
	passOK(t, newPDPager(t, srv, &fakeSource{items: []Waiting{w}}))
	if _, ok := srv.incidents[Key(w)].details["link"]; ok {
		t.Fatal("an empty link was sent, and the server refuses an empty value")
	}
}

// TestAKeyThatTheServerRefusesMakesNoCall: the adapter checks the format before the call.
func TestAKeyThatTheServerRefusesMakesNoCall(t *testing.T) {
	for _, id := range []string{"has space", "bad\x00id", "é"} {
		srv := newPD()
		w := wait(id, 5*time.Hour)
		p := newPDPager(t, srv, &fakeSource{items: []Waiting{w}})
		if _, err := p.Pass(context.Background()); err == nil {
			t.Errorf("id %q: want an error", id)
		}
		if srv.events != 0 {
			t.Errorf("id %q: a call was made", id)
		}
	}
	if err := checkKey("wait:merge_refused:f-1:1763719200"); err != nil {
		t.Fatalf("a good key: %v", err)
	}
}

func TestTextHelpersCutAtACharacterAndStripControls(t *testing.T) {
	long := strings.Repeat("日", 600) // 1800 bytes
	if got := clipBytes(long, maxSummary); len(got) != 1023 || !utf8.ValidString(got) {
		t.Fatalf("%d bytes, valid %v", len(got), utf8.ValidString(got))
	}
	if got := clipBytes(strings.Repeat("é", 600), maxSummary); len(got) != 1024 || !utf8.ValidString(got) {
		t.Fatalf("%d bytes", len(got))
	}
	if got := line("a\x00b\x1b[0m\u0085\tc\xff"); strings.ContainsAny(got, "\x00\x1b\u0085\t") || !utf8.ValidString(got) {
		t.Fatalf("line = %q", got)
	}
}
