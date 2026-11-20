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

	"github.com/zeroroot-ai/intake-agent/internal/intake"
	"github.com/zeroroot-ai/intake-agent/internal/recipe"
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

// MarkerKind is the kind of the memory observation that records a marker.
const MarkerKind = "intake-marker"

// Wire is the part of the callback client that the agent uses.
// *serve.CallbackClient satisfies it.
type Wire interface {
	CallToolProto(ctx context.Context, req *harnesspb.CallToolProtoRequest) (*harnesspb.CallToolProtoResponse, error)
	SubmitFinding(ctx context.Context, req *harnesspb.SubmitFindingRequest) (*harnesspb.SubmitFindingResponse, error)
	Observe(ctx context.Context, req *harnesspb.ObserveRequest) (*harnesspb.ObserveResponse, error)
	QueryNodes(ctx context.Context, req *harnesspb.QueryNodesRequest) (*harnesspb.QueryNodesResponse, error)
}

var _ Wire = (*serve.CallbackClient)(nil)

// Harness implements intake.Daemon and intake.Markers over a Wire.
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

var (
	_ intake.Daemon  = (*Harness)(nil)
	_ intake.Markers = (*Harness)(nil)
)

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

func (h *Harness) callMeta(ctx context.Context, name string, input []byte) ([]byte, string, error) {
	resp, err := h.wire.CallToolProto(ctx, &harnesspb.CallToolProtoRequest{Name: name, InputJson: input})
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", name, err)
	}
	if e := resp.GetError(); e != nil && e.GetMessage() != "" {
		return nil, resp.GetToolCallId(), fmt.Errorf("%s: %s", name, e.GetMessage())
	}
	return resp.GetOutputJson(), resp.GetToolCallId(), nil
}

// ResultKey is the stable identity of one result of one connector. Both the
// finding and the Alert use it, so a second read of a result updates it.
func ResultKey(connector, resultID string) string {
	sum := sha256.Sum256([]byte(connector + "\x00" + resultID))
	return "intake:" + hex.EncodeToString(sum[:16])
}

// RaiseFlaw submits the flaw as a finding. The idempotency key comes from the
// connector and the result id, and the finding cites the recorded call.
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
		return fmt.Errorf("submit finding: %w", err)
	}
	if e := resp.GetError(); e != nil && e.GetMessage() != "" {
		return fmt.Errorf("submit finding: %s", e.GetMessage())
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
	return h.observe(ctx, &harnesspb.ObserveRequest{
		Observation: &harnesspb.ObserveRequest_LifecycleEntity{LifecycleEntity: obs},
	})
}

func (h *Harness) observe(ctx context.Context, req *harnesspb.ObserveRequest) error {
	resp, err := h.wire.Observe(ctx, req)
	if err != nil {
		return fmt.Errorf("observe: %w", err)
	}
	if e := resp.GetError(); e != nil && e.GetMessage() != "" {
		return fmt.Errorf("observe: %s", e.GetMessage())
	}
	return nil
}

// Save records the marker of a connector as a memory observation on the
// Timeline.
func (h *Harness) Save(ctx context.Context, connector string, m recipe.Marker) error {
	text, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode the marker: %w", err)
	}
	return h.observe(ctx, &harnesspb.ObserveRequest{
		Observation: &harnesspb.ObserveRequest_Memory{Memory: &harnesspb.MemoryObservation{
			Text:      string(text),
			Kind:      MarkerKind,
			Tags:      []string{MarkerKind, connector},
			SourceRef: connector,
		}},
	})
}

// Load reads the last marker of each connector back from the graph.
//
// The query and the field that holds the text are NOT verified against a
// running daemon. See README.md, "Open points".
func (h *Harness) Load(ctx context.Context) (map[string]recipe.Marker, error) {
	resp, err := h.wire.QueryNodes(ctx, &harnesspb.QueryNodesRequest{Query: markerQuery()})
	if err != nil {
		return nil, fmt.Errorf("query the markers: %w", err)
	}
	if e := resp.GetError(); e != nil && e.GetMessage() != "" {
		return nil, fmt.Errorf("query the markers: %s", e.GetMessage())
	}
	out := map[string]recipe.Marker{}
	newest := map[string]int64{}
	for _, r := range resp.GetResults() {
		n := r.GetNode()
		var m recipe.Marker
		if err := json.Unmarshal([]byte(strings.TrimSpace(n.GetContent())), &m); err != nil || m.Cursor == "" {
			continue
		}
		conn := ""
		if p, ok := n.GetProperties()["source_ref"]; ok {
			conn = p.GetStringValue()
		}
		if conn == "" {
			continue
		}
		if at := n.GetUpdatedAt(); at >= newest[conn] {
			newest[conn] = at
			out[conn] = m
		}
	}
	return out, nil
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
