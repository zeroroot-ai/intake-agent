// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sender

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"

	"github.com/zeroroot-ai/sdk/a2ainbound"
)

var secret = []byte("shared-secret")

// now is the clock of the tests.
var now = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func stamp(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

// sign signs the timestamp, the id and the body.
func sign(ts, id string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts + "." + id + "."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// fakeGibson is the inbound A2A endpoint of Gibson. It starts a mission for a
// call that has a grant with the ceiling mission:originate, and for no other.
type fakeGibson struct {
	a2asrv.RequestHandler
	srv *httptest.Server

	mu       sync.Mutex
	missions []*a2a.Message
	reject   bool
}

// The two tokens that the fake edge knows.
const (
	tokenOriginate = "grant-with-mission-originate"
	tokenNoCeiling = "grant-without-the-ceiling"
)

func newGibson(t *testing.T) *fakeGibson {
	t.Helper()
	g := &fakeGibson{}
	rpc := a2asrv.NewJSONRPCHandler(g)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /a2a/inbound/{agent}", func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("x-capability-grant") {
		case tokenOriginate:
			rpc.ServeHTTP(w, r)
		case tokenNoCeiling:
			http.Error(w, "not a caller identity", http.StatusForbidden)
		default:
			http.Error(w, "no capability grant", http.StatusUnauthorized)
		}
	})
	g.srv = httptest.NewTLSServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGibson) SendMessage(_ context.Context, req *a2a.SendMessageRequest) (a2a.SendMessageResult, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.reject {
		return &a2a.Task{ID: "refused-1", ContextID: "refused-1", Status: a2a.TaskStatus{State: a2a.TaskStateRejected}}, nil
	}
	g.missions = append(g.missions, req.Message)
	return &a2a.Task{ID: "mission-1", ContextID: "ctx-1", Status: a2a.TaskStatus{State: a2a.TaskStateSubmitted}}, nil
}

func (g *fakeGibson) started() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.missions)
}

type stubSigner struct {
	token string
	err   error
}

func (s stubSigner) SignPath(string) (string, error) { return s.token, s.err }

func newSender(t *testing.T, g *fakeGibson, signer a2ainbound.PathSigner) (*Sender, *bytes.Buffer) {
	t.Helper()
	c, err := a2ainbound.NewClient(a2ainbound.Config{
		BaseURL: g.srv.URL, Signer: signer, Transport: g.srv.Client().Transport,
	})
	if err != nil {
		t.Fatalf("a2a client: %v", err)
	}
	var logs bytes.Buffer
	s, err := New(c, Config{Agent: "incident-response", Source: "mock-edr", Secret: secret,
		Now: func() time.Time { return now }},
		slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return s, &logs
}

// post sends a webhook with the given headers. An empty value sets no header.
func post(s http.Handler, body []byte, ts, id, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	for k, v := range map[string]string{DefaultTimestampHeader: ts, DefaultIDHeader: id, DefaultSignatureHeader: sig} {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

var eventSeq int

// postGood sends a webhook that is signed, fresh and new.
func postGood(s http.Handler, body []byte) *httptest.ResponseRecorder {
	eventSeq++
	id, ts := fmt.Sprintf("evt-%d", eventSeq), stamp(now)
	return post(s, body, ts, id, sign(ts, id, body))
}

func TestAWebhookFromAMockToolStartsOneMission(t *testing.T) {
	g := newGibson(t)
	s, _ := newSender(t, g, stubSigner{token: tokenOriginate})
	body := []byte(`{"alert":"a-7","severity":"high","host":"10.0.0.9"}`)

	rec := postGood(s, body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got["task_id"] != "mission-1" {
		t.Fatalf("body %s, err %v", rec.Body, err)
	}
	if g.started() != 1 {
		t.Fatalf("Gibson started %d missions, want 1", g.started())
	}
	msg := g.missions[0]
	if len(msg.Parts) != 1 {
		t.Fatalf("the message has %d parts, want one text part and no target", len(msg.Parts))
	}
	text := msg.Parts[0].Text()
	if !strings.Contains(text, "mock-edr") || !strings.Contains(text, `"alert":"a-7"`) {
		t.Fatalf("the text lacks the source or the payload: %q", text)
	}
}

func TestASenderWithNoGrantStartsNoMission(t *testing.T) {
	cases := map[string]stubSigner{
		"the signer holds no grant":             {err: errors.New("no grant: the identity is not enrolled")},
		"the token is not a grant":              {token: "garbage"},
		"the identity has no mission:originate": {token: tokenNoCeiling},
	}
	for name, signer := range cases {
		t.Run(name, func(t *testing.T) {
			g := newGibson(t)
			s, _ := newSender(t, g, signer)
			body := []byte(`{"alert":"a-7"}`)
			rec := postGood(s, body)
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status %d, want 502: %s", rec.Code, rec.Body)
			}
			if g.started() != 0 {
				t.Fatalf("Gibson started %d missions, want 0", g.started())
			}
		})
	}
}

func TestAnUnsignedOrWronglySignedWebhookSendsNothing(t *testing.T) {
	g := newGibson(t)
	s, _ := newSender(t, g, stubSigner{token: tokenOriginate})
	body := []byte(`{"alert":"a-7"}`)
	ts, id := stamp(now), "evt-x"
	good := sign(ts, id, body)
	for name, c := range map[string]struct{ ts, id, sig string }{
		"no signature":       {ts, id, ""},
		"no timestamp":       {"", id, good},
		"no id":              {ts, "", good},
		"wrong body":         {ts, id, sign(ts, id, []byte(`{"alert":"a-8"}`))},
		"another id":         {ts, "evt-y", good},
		"another timestamp":  {stamp(now.Add(time.Second)), id, good},
		"no prefix":          {ts, id, strings.TrimPrefix(good, "sha256=")},
		"not hex":            {ts, id, "sha256=zz"},
		"empty after prefix": {ts, id, "sha256="},
	} {
		if rec := post(s, body, c.ts, c.id, c.sig); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
		}
	}
	if g.started() != 0 {
		t.Fatalf("Gibson started %d missions, want 0", g.started())
	}
}

func TestABodyChangedAfterSigningIsRefused(t *testing.T) {
	g := newGibson(t)
	s, _ := newSender(t, g, stubSigner{token: tokenOriginate})
	ts, id := stamp(now), "evt-1"
	sig := sign(ts, id, []byte(`{"host":"10.0.0.9"}`))
	if rec := post(s, []byte(`{"host":"10.0.0.10"}`), ts, id, sig); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if g.started() != 0 {
		t.Fatal("a changed body started a mission")
	}
}

func TestAnOldOrAFutureTimestampIsRefusedEvenWithAGoodSignature(t *testing.T) {
	g := newGibson(t)
	s, _ := newSender(t, g, stubSigner{token: tokenOriginate})
	body := []byte(`{"alert":"a-7"}`)
	for name, at := range map[string]time.Time{
		"old":               now.Add(-DefaultWindow - time.Second),
		"far in the past":   now.Add(-24 * time.Hour),
		"future":            now.Add(DefaultWindow + time.Second),
		"far in the future": now.Add(24 * time.Hour),
	} {
		ts, id := stamp(at), "evt-"+name
		if rec := post(s, body, ts, id, sign(ts, id, body)); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
		}
	}
	// The edge of the window is inside it.
	for name, at := range map[string]time.Time{"oldest": now.Add(-DefaultWindow), "latest": now.Add(DefaultWindow)} {
		ts, id := stamp(at), "evt-"+name
		if rec := post(s, body, ts, id, sign(ts, id, body)); rec.Code != http.StatusAccepted {
			t.Errorf("%s: status %d, want 202", name, rec.Code)
		}
	}
	if g.started() != 2 {
		t.Fatalf("Gibson started %d missions, want 2", g.started())
	}
}

func TestAReplayedEventStartsOneMission(t *testing.T) {
	g := newGibson(t)
	s, _ := newSender(t, g, stubSigner{token: tokenOriginate})
	body := []byte(`{"alert":"a-7"}`)
	ts, id := stamp(now), "evt-1"
	sig := sign(ts, id, body)
	if rec := post(s, body, ts, id, sig); rec.Code != http.StatusAccepted {
		t.Fatalf("first: status %d", rec.Code)
	}
	for range 2 {
		if rec := post(s, body, ts, id, sig); rec.Code != http.StatusConflict {
			t.Fatalf("replay: status %d, want 409", rec.Code)
		}
	}
	if g.started() != 1 {
		t.Fatalf("Gibson started %d missions, want 1", g.started())
	}
}

func TestAnEventThatFailedToSendCanBeRetriedWithTheSameID(t *testing.T) {
	g := newGibson(t)
	failing, _ := newSender(t, g, stubSigner{err: errors.New("no grant")})
	body := []byte(`{"alert":"a-7"}`)
	ts, id := stamp(now), "evt-1"
	sig := sign(ts, id, body)
	if rec := post(failing, body, ts, id, sig); rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rec.Code)
	}
	// The same sender state: swap the originator for one that works.
	good, _ := newSender(t, g, stubSigner{token: tokenOriginate})
	good.seen = failing.seen
	if rec := post(good, body, ts, id, sig); rec.Code != http.StatusAccepted {
		t.Fatalf("retry: status %d, want 202", rec.Code)
	}
}

func TestTheStoreOfEventIDsIsBounded(t *testing.T) {
	g := newGibson(t)
	s, _ := newSender(t, g, stubSigner{token: tokenOriginate})
	s.seen.max = 2
	body := []byte(`{}`)
	codes := make([]int, 0, 3)
	for _, id := range []string{"a", "b", "c"} {
		ts := stamp(now)
		codes = append(codes, post(s, body, ts, id, sign(ts, id, body)).Code)
	}
	if codes[0] != 202 || codes[1] != 202 || codes[2] != http.StatusServiceUnavailable {
		t.Fatalf("codes %v", codes)
	}
	// Time passes. The ids of the first two events are not needed any more.
	later := now.Add(2*DefaultWindow + time.Second)
	s.cfg.Now = func() time.Time { return later }
	ts := stamp(later)
	if rec := post(s, body, ts, "c", sign(ts, "c", body)); rec.Code != http.StatusAccepted {
		t.Fatalf("after the window: status %d, want 202", rec.Code)
	}
}

func TestAMessageThatGibsonRejectsIsA403(t *testing.T) {
	g := newGibson(t)
	g.reject = true
	s, _ := newSender(t, g, stubSigner{token: tokenOriginate})
	body := []byte(`{"alert":"a-7"}`)
	if rec := postGood(s, body); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if g.started() != 0 {
		t.Fatal("a rejected message started a mission")
	}
}

func TestABodyOverTheLimitIsRefused(t *testing.T) {
	g := newGibson(t)
	s, _ := newSender(t, g, stubSigner{token: tokenOriginate})
	s.cfg.MaxBody = 16
	body := bytes.Repeat([]byte("a"), 64)
	if rec := postGood(s, body); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
	if g.started() != 0 {
		t.Fatal("an oversize body started a mission")
	}
}

func TestABigBodyIsCutInTheMessageAndTheMessageSaysSo(t *testing.T) {
	g := newGibson(t)
	s, _ := newSender(t, g, stubSigner{token: tokenOriginate})
	body := bytes.Repeat([]byte("a"), maxText+10)
	if rec := postGood(s, body); rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	text := g.missions[0].Parts[0].Text()
	if !strings.Contains(text, "the sender cut the body") || len(text) > maxText+200 {
		t.Fatalf("the text is %d bytes and has no cut note", len(text))
	}
}

func TestOnlyPostIsAccepted(t *testing.T) {
	g := newGibson(t)
	s, _ := newSender(t, g, stubSigner{token: tokenOriginate})
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/webhook", http.NoBody))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405", rec.Code)
	}
}

func TestNewNeedsEachPart(t *testing.T) {
	g := newGibson(t)
	c, err := a2ainbound.NewClient(a2ainbound.Config{BaseURL: g.srv.URL, Signer: stubSigner{}})
	if err != nil {
		t.Fatal(err)
	}
	ok := Config{Agent: "a", Source: "s", Secret: secret}
	for name, cfg := range map[string]Config{
		"no agent":  {Source: "s", Secret: secret},
		"no source": {Agent: "a", Secret: secret},
		"no secret": {Agent: "a", Source: "s"},
	} {
		if _, err := New(c, cfg, nil); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := New(nil, ok, nil); err == nil {
		t.Error("no originator: want an error")
	}
}
