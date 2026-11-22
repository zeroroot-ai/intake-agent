// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon is the one place where the agent talks to the harness.
//
// It turns the calls of the intake package into calls of the harness callback
// service. The daemon calls the connector. The agent never does.
package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/intake-agent/internal/intake"
	"github.com/zeroroot-ai/intake-agent/internal/mirror"
	"github.com/zeroroot-ai/intake-agent/internal/pager"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/finding"
	"github.com/zeroroot-ai/sdk/serve"
)

// The two meta-tools of the harness (ADR-0065).
const (
	searchTool = "search_tools"
	invokeTool = "invoke_tool"
)

// searchLimit is the largest number of tool candidates that one search asks for.
const searchLimit = 500

// Wire is the part of the callback client that the agent uses.
// *serve.CallbackClient satisfies it.
type Wire interface {
	CallToolProto(ctx context.Context, req *harnesspb.CallToolProtoRequest) (*harnesspb.CallToolProtoResponse, error)
	SubmitFinding(ctx context.Context, req *harnesspb.SubmitFindingRequest) (*harnesspb.SubmitFindingResponse, error)
	Observe(ctx context.Context, req *harnesspb.ObserveRequest) (*harnesspb.ObserveResponse, error)
}

var _ Wire = (*serve.CallbackClient)(nil)

// Harness implements intake.Daemon over a Wire.
type Harness struct {
	wire  Wire
	agent string
}

// New builds a harness client. agent is the name that the findings carry.
func New(w Wire, agent string) (*Harness, error) {
	if w == nil {
		return nil, errors.New("daemon: no wire")
	}
	return &Harness{wire: w, agent: agent}, nil
}

var _ intake.Daemon = (*Harness)(nil)

// ErrNoMarkerStore is the refusal of NewMarkers.
var ErrNoMarkerStore = errors.New("daemon: no marker store: " +
	"the harness callback service has no call to write or read a Timeline marker event")

// NewMarkers returns the marker store of the agent. It always fails now.
//
// A marker must have one author and one order. Only the daemon can give both:
// it writes the marker as a Timeline event for the identity of this agent, and
// it returns the last such event of one connector. The callback service of the
// SDK has no call for this. A memory node is not a marker store: a query of
// memory nodes has no order and no author filter, so the newest marker can drop
// out of the result and any writer in the tenant can forge one.
func NewMarkers(Wire) (intake.Markers, error) { return nil, ErrNoMarkerStore }

// ErrNoItemSource is the refusal of NewItemSource.
var ErrNoItemSource = errors.New("daemon: no item source: " +
	"the harness callback service has no call to list the findings and incidents of the tenant with their status")

// NewItemSource returns the source of the ticket mirror. It always fails now.
//
// GetFindings of the callback service is scoped to one mission, and a member
// has no mission. The tenant call that lists findings needs a user or a service
// identity, and a member is an agent identity. See README.md, "Open points".
func NewItemSource(Wire) (mirror.Source, error) { return nil, ErrNoItemSource }

// ErrNoWaitSource is the refusal of NewWaitSource.
var ErrNoWaitSource = errors.New("daemon: no wait source: " +
	"the harness callback service has no call for ListWaitingOnPerson or for the wait limit of the tenant")

// NewWaitSource returns the source of the pager. It always fails now.
//
// ListWaitingOnPerson is a call of the WorldService. Its authz rule admits a
// user and a service identity, and a member is an agent identity. The wait limit
// of the tenant has no setting and no API. See README.md, "Open points".
func NewWaitSource(Wire) (pager.Source, error) { return nil, ErrNoWaitSource }

// Tools lists the tools of the enabled connectors through search_tools.
func (h *Harness) Tools(ctx context.Context) ([]intake.Tool, error) {
	in, err := json.Marshal(map[string]any{"sources": []string{"mcp"}, "limit": searchLimit})
	if err != nil {
		return nil, fmt.Errorf("encode the search: %w", err)
	}
	out, _, err := h.callMeta(ctx, searchTool, in)
	if err != nil {
		return nil, err
	}
	var res struct {
		Candidates []struct {
			Connector string `json:"connector"`
			Tool      string `json:"tool"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("read the search result: %w", err)
	}
	tools := make([]intake.Tool, 0, len(res.Candidates))
	for _, c := range res.Candidates {
		if c.Connector != "" && c.Tool != "" {
			tools = append(tools, intake.Tool{Connector: c.Connector, Name: c.Tool})
		}
	}
	return tools, nil
}

// Invoke calls one tool through invoke_tool. The daemon checks the grant and
// records the call.
func (h *Harness) Invoke(ctx context.Context, connector, tool string, args map[string]any) (intake.Call, error) {
	in, err := json.Marshal(map[string]any{"id": "mcp:" + connector + ":" + tool, "args": args})
	if err != nil {
		return intake.Call{}, fmt.Errorf("encode the call: %w", err)
	}
	out, callID, err := h.callMeta(ctx, invokeTool, in)
	if err != nil {
		return intake.Call{ID: callID}, err
	}
	var res struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return intake.Call{ID: callID}, fmt.Errorf("read the call result: %w", err)
	}
	return intake.Call{JSON: res.Result, ID: callID}, nil
}

func (h *Harness) callMeta(ctx context.Context, name string, input []byte) (output []byte, callID string, err error) {
	resp, err := h.wire.CallToolProto(ctx, &harnesspb.CallToolProtoRequest{Name: name, InputJson: input})
	if err != nil {
		return nil, "", wireErr(name, err)
	}
	if e := resp.GetError(); e != nil {
		return nil, resp.GetToolCallId(), refusal(name, e)
	}
	return resp.GetOutputJson(), resp.GetToolCallId(), nil
}

// wireErr wraps an error of the wire. An Unauthenticated status means that the
// daemon refused the grant, for example because it expired. No later call can
// pass with that grant, so the error also wraps intake.ErrGrant.
func wireErr(op string, err error) error {
	if status.Code(err) == codes.Unauthenticated {
		return fmt.Errorf("%s: %w: %w", op, intake.ErrGrant, err)
	}
	return fmt.Errorf("%s: %w", op, err)
}

// refusal turns a HarnessError into an error. A HarnessError with no message
// is still a refusal, so the error names its code.
func refusal(op string, e *harnesspb.HarnessError) error {
	msg := e.GetMessage()
	if msg == "" {
		msg = "refused with no message"
	}
	return fmt.Errorf("%s: %s: %s", op, e.GetCode(), msg)
}

// ResultKey is the idempotency key of the finding of one result of one
// connector.
func ResultKey(connector, resultID string) string {
	sum := sha256.Sum256([]byte(connector + "\x00" + resultID))
	return "intake:" + hex.EncodeToString(sum[:16])
}

// RaiseFlaw submits the flaw as a finding, and the finding cites the recorded
// call.
//
// The idempotency key is ResultKey(connector, result id). The daemon of the
// gibson branch integration/blue-team derives the id of the finding from the
// tenant, the agent name and this key (gibson#1448). It writes the finding with
// an upsert on that id, so a second read of one result updates the same
// finding. The daemon on gibson main does not do this: there each submit gets a
// new finding id. See README.md, "Open points".
func (h *Harness) RaiseFlaw(ctx context.Context, ho intake.Handoff) error {
	f := &finding.Finding{
		AgentName:   h.agent,
		Title:       ho.Item.Title,
		Description: ho.Item.Description,
		Category:    string(ho.Class),
		Severity:    severity(ho.Item.Severity),
		Confidence:  1,
		Status:      finding.StatusOpen,
		Technique:   ho.Tool,
		Tags: []string{
			"intake",
			"intake:connector=" + ho.Connector,
			"intake:result=" + ho.Item.ID,
		},
	}
	f.CiteToolCalls(ho.CallID)
	resp, err := h.wire.SubmitFinding(ctx, &harnesspb.SubmitFindingRequest{
		Finding:        serve.FindingToProto(f),
		IdempotencyKey: ResultKey(ho.Connector, ho.Item.ID),
		ToolCallIds:    f.ToolCallIDs,
	})
	if err != nil {
		return wireErr("submit finding", err)
	}
	if e := resp.GetError(); e != nil {
		return refusal("submit finding", e)
	}
	return nil
}

// RaiseAlert reports the alert as a sighting of an Alert entity. The identity
// is the connector and the result id, so a second sighting enriches the node.
func (h *Harness) RaiseAlert(ctx context.Context, ho intake.Handoff) error {
	obs := &harnesspb.LifecycleEntityObservation{
		Label:        "Alert",
		IdProperties: map[string]string{"connector": ho.Connector, "result_id": ho.Item.ID},
		Properties: map[string]string{
			"tool":     ho.Tool,
			"class":    string(ho.Class),
			"title":    ho.Item.Title,
			"detail":   ho.Item.Description,
			"severity": ho.Item.Severity,
			"call_id":  ho.CallID,
		},
	}
	resp, err := h.wire.Observe(ctx, &harnesspb.ObserveRequest{
		Observation: &harnesspb.ObserveRequest_LifecycleEntity{LifecycleEntity: obs},
	})
	if err != nil {
		return wireErr("observe", err)
	}
	if e := resp.GetError(); e != nil {
		return refusal("observe", e)
	}
	return nil
}

func severity(s string) finding.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}
