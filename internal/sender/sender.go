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
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

const (
	// DefaultSignatureHeader is the header that holds the signature of a webhook.
	DefaultSignatureHeader = "X-Webhook-Signature"
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
	// the body.
	SignatureHeader string
	// MaxBody is the largest accepted body. The default is DefaultMaxBody.
	MaxBody int64
}

// Sender is the http.Handler of one webhook endpoint.
type Sender struct {
	origin Originator
	cfg    Config
	log    *slog.Logger
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
	if log == nil {
		log = slog.Default()
	}
	return &Sender{origin: o, cfg: cfg, log: log}, nil
}

// ServeHTTP receives one webhook.
//
//	202  Gibson accepted the message and started a mission.
//	401  The signature is missing or wrong. Nothing was sent.
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
	if !s.signed(r.Header.Get(s.cfg.SignatureHeader), body) {
		s.log.Warn("sender: webhook refused: the signature is missing or wrong", "source", s.cfg.Source)
		reply(w, http.StatusUnauthorized, map[string]string{"error": "the signature is missing or wrong"})
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

// signed reports whether the header holds the HMAC-SHA256 of the body.
func (s *Sender) signed(header string, body []byte) bool {
	got, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return false
	}
	sig, err := hex.DecodeString(got)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, s.cfg.Secret)
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
