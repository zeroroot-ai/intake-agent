// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package sender turns a webhook of a tool of the buyer into one A2A message to
// Gibson (gibson#1451).
//
// Gibson has no webhook receiver. A sender runs next to the tool of the buyer.
// It receives the webhook, checks its signature and sends one A2A message to a
// published Gibson agent. Gibson then starts one mission from the definition
// that the tenant published for that agent.
//
// The sender is an enrolled identity with the ceiling mission:originate
// (ADR-0045). It signs each call with a Capability Grant. A sender with no grant
// starts no mission: Gibson refuses the call, and the sender answers the tool
// with an error.
//
// The text of the webhook is task input only. The sender sends no target, so
// the webhook can never add a target to the mission.
package sender

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

const (
	// DefaultSignatureHeader is the header that holds the signature of a webhook.
	DefaultSignatureHeader = "X-Webhook-Signature"
	// DefaultTimestampHeader holds the time of the event in Unix seconds.
	DefaultTimestampHeader = "X-Webhook-Timestamp"
	// DefaultIDHeader holds the id of the event. Two events never share an id.
	DefaultIDHeader = "X-Webhook-Id"
	// DefaultWindow is the largest age of an event, and the largest distance
	// into the future that the sender accepts.
	DefaultWindow = 5 * time.Minute
	// DefaultMaxSeen is the largest number of event ids that the sender holds.
	DefaultMaxSeen = 10000
	maxIDLen       = 200
	// DefaultMaxBody is the largest webhook body that the sender accepts.
	DefaultMaxBody int64 = 1 << 20
	// maxText is the largest part of the body that goes into the message. The
	// message names the cut when it makes one.
	maxText = 32 << 10
)

// Originator sends one message to a published Gibson agent. *a2ainbound.Client
// is an Originator.
type Originator interface {
	SendMessage(ctx context.Context, agent, text string, targets ...string) (*a2a.Task, error)
}

// Config configures a Sender.
type Config struct {
	// Agent is the name of the published Gibson agent that gets the message.
	Agent string
	// Source names the tool that sends the webhook. It is in the message.
	Source string
	// Secret is the shared secret that signs each webhook.
	Secret []byte
	// SignatureHeader is the header of the signature. The default is
	// DefaultSignatureHeader. The value is "sha256=" and the hex HMAC-SHA256 of
	// the signed text. The signed text is the timestamp, a dot, the event id, a
	// dot and the body. The timestamp and the id are so part of the signature.
	SignatureHeader string
	// TimestampHeader and IDHeader name the headers of the time and the id of the
	// event. The defaults are DefaultTimestampHeader and DefaultIDHeader.
	TimestampHeader, IDHeader string
	// Window is the largest age and the largest lead of an event. The default is
	// DefaultWindow.
	Window time.Duration
	// MaxSeen is the largest number of event ids that the sender holds. The
	// default is DefaultMaxSeen.
	MaxSeen int
	// Now is the clock. The default is time.Now.
	Now func() time.Time
	// MaxBody is the largest accepted body. The default is DefaultMaxBody.
	MaxBody int64
}

// Sender is the http.Handler of one webhook endpoint.
type Sender struct {
	origin Originator
	cfg    Config
	log    *slog.Logger
	seen   *seenStore
}

// seenStore holds the ids of the events that the sender took. It lives in the
// memory of one process, so replay protection holds for one replica only.
// Two replicas, or a restart inside the window, can take a repeated event.
type seenStore struct {
	mu  sync.Mutex
	max int
	ids map[string]time.Time // id -> the time after which the id is not needed
}

var errStoreFull = errors.New("the store of event ids is full")

// reserve holds the id until expiry. It reports false for an id that it holds.
func (s *seenStore) reserve(id string, expiry, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if until, ok := s.ids[id]; ok && until.After(now) {
		return false, nil
	}
	if len(s.ids) >= s.max {
		for k, until := range s.ids {
			if !until.After(now) {
				delete(s.ids, k)
			}
		}
		if len(s.ids) >= s.max {
			return false, errStoreFull
		}
	}
	s.ids[id] = expiry
	return true, nil
}

func (s *seenStore) release(id string) {
	s.mu.Lock()
	delete(s.ids, id)
	s.mu.Unlock()
}

// New builds a Sender.
func New(o Originator, cfg Config, log *slog.Logger) (*Sender, error) {
	switch {
	case o == nil:
		return nil, errors.New("sender: an originator is required")
	case cfg.Agent == "":
		return nil, errors.New("sender: the name of the Gibson agent is required")
	case cfg.Source == "":
		return nil, errors.New("sender: the name of the source tool is required")
	case len(cfg.Secret) == 0:
		return nil, errors.New("sender: the webhook secret is required, because an unsigned webhook is refused")
	}
	if cfg.SignatureHeader == "" {
		cfg.SignatureHeader = DefaultSignatureHeader
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = DefaultMaxBody
	}
	if cfg.TimestampHeader == "" {
		cfg.TimestampHeader = DefaultTimestampHeader
	}
	if cfg.IDHeader == "" {
		cfg.IDHeader = DefaultIDHeader
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.MaxSeen <= 0 {
		cfg.MaxSeen = DefaultMaxSeen
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Sender{origin: o, cfg: cfg, log: log,
		seen: &seenStore{max: cfg.MaxSeen, ids: map[string]time.Time{}}}, nil
}

// ServeHTTP receives one webhook.
//
//	202  Gibson accepted the message and started a mission.
//	401  The signature, the timestamp or the event id is missing or wrong, or
//	     the event is older than the window or too far ahead. Nothing was sent.
//	409  The event id was already taken inside the window. Nothing was sent.
//	503  The store of event ids is full. A retry can help.
//	403  Gibson rejected the message (the Task state "rejected"). A retry
//	     cannot help.
//	405  The method is not POST.
//	413  The body is too large.
//	502  Gibson refused the sender or could not be reached. A retry can help.
func (s *Sender) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		reply(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			reply(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "the body is too large"})
			return
		}
		reply(w, http.StatusBadRequest, map[string]string{"error": "the body is not readable"})
		return
	}
	stamp, id := r.Header.Get(s.cfg.TimestampHeader), r.Header.Get(s.cfg.IDHeader)
	if id == "" || len(id) > maxIDLen || !s.signed(r.Header.Get(s.cfg.SignatureHeader), stamp, id, body) {
		s.log.Warn("sender: webhook refused: the signature, the timestamp or the id is missing or wrong",
			"source", s.cfg.Source)
		reply(w, http.StatusUnauthorized, map[string]string{"error": "the signature is missing or wrong"})
		return
	}
	// The timestamp is signed, so it is read only after the signature is good.
	secs, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		reply(w, http.StatusUnauthorized, map[string]string{"error": "the timestamp is not a number"})
		return
	}
	sent, now := time.Unix(secs, 0), s.cfg.Now()
	if d := now.Sub(sent); d > s.cfg.Window || d < -s.cfg.Window {
		s.log.Warn("sender: webhook refused: the timestamp is outside the window", "source", s.cfg.Source, "id", id)
		reply(w, http.StatusUnauthorized, map[string]string{"error": "the timestamp is outside the window"})
		return
	}
	fresh, err := s.seen.reserve(id, sent.Add(s.cfg.Window), now)
	if err != nil {
		s.log.Error("sender: cannot hold the event id", "err", err)
		reply(w, http.StatusServiceUnavailable, map[string]string{"error": "try again later"})
		return
	}
	if !fresh {
		s.log.Warn("sender: webhook refused: the event id was already taken", "source", s.cfg.Source, "id", id)
		reply(w, http.StatusConflict, map[string]string{"error": "the event id was already taken"})
		return
	}

	task, err := s.origin.SendMessage(r.Context(), s.cfg.Agent, s.text(body))
	if err != nil {
		// The cause can name the platform. It stays in the log.
		if errors.Is(err, a2a.ErrUnauthenticated) || errors.Is(err, a2a.ErrUnauthorized) {
			s.log.Error("sender: Gibson refused the sender: it needs an enrolled identity with the ceiling mission:originate",
				"agent", s.cfg.Agent, "err", err)
		} else {
			s.log.Error("sender: send failed", "agent", s.cfg.Agent, "err", err)
		}
		// The tool retries a 502 with the same id. The retry must not be a replay.
		s.seen.release(id)
		reply(w, http.StatusBadGateway, map[string]string{"error": "Gibson did not accept the message"})
		return
	}
	if task.Status.State == a2a.TaskStateRejected {
		s.log.Warn("sender: Gibson rejected the message", "agent", s.cfg.Agent)
		reply(w, http.StatusForbidden, map[string]string{"error": "Gibson rejected the message"})
		return
	}
	s.log.Info("sender: mission started", "agent", s.cfg.Agent, "source", s.cfg.Source, "task", string(task.ID))
	reply(w, http.StatusAccepted, map[string]string{"task_id": string(task.ID), "state": string(task.Status.State)})
}

// signed reports whether the header holds the HMAC-SHA256 of the signed text.
// The comparison takes constant time.
func (s *Sender) signed(header, stamp, id string, body []byte) bool {
	got, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return false
	}
	sig, err := hex.DecodeString(got)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, s.cfg.Secret)
	mac.Write([]byte(stamp + "." + id + "."))
	mac.Write(body)
	return hmac.Equal(sig, mac.Sum(nil))
}

// text builds the text of the message from the body of the webhook.
func (s *Sender) text(body []byte) string {
	cut := ""
	if len(body) > maxText {
		body, cut = body[:maxText], fmt.Sprintf("\n[the sender cut the body at %d bytes]", maxText)
	}
	return fmt.Sprintf("A webhook arrived from %s.\n%s%s", s.cfg.Source, body, cut)
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
