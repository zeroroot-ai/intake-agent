// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/intake-agent/internal/intake"
	"github.com/zeroroot-ai/intake-agent/internal/recipe"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

var errWire = errors.New("wire down")

type fakeWire struct {
	tool     []*harnesspb.CallToolProtoRequest
	toolResp *harnesspb.CallToolProtoResponse
	findings []*harnesspb.SubmitFindingRequest
	observed []*harnesspb.ObserveRequest
	query    *harnesspb.QueryNodesResponse
	err      error
	respErr  *harnesspb.HarnessError
}

func (w *fakeWire) CallToolProto(_ context.Context, r *harnesspb.CallToolProtoRequest) (*harnesspb.CallToolProtoResponse, error) {
	w.tool = append(w.tool, r)
	return w.toolResp, w.err
}

func (w *fakeWire) SubmitFinding(_ context.Context, r *harnesspb.SubmitFindingRequest) (*harnesspb.SubmitFindingResponse, error) {
	w.findings = append(w.findings, r)
	return &harnesspb.SubmitFindingResponse{Error: w.respErr}, w.err
}

func (w *fakeWire) Observe(_ context.Context, r *harnesspb.ObserveRequest) (*harnesspb.ObserveResponse, error) {
	w.observed = append(w.observed, r)
	return &harnesspb.ObserveResponse{Error: w.respErr}, w.err
}

func (w *fakeWire) QueryNodes(context.Context, *harnesspb.QueryNodesRequest) (*harnesspb.QueryNodesResponse, error) {
	return w.query, w.err
}

func newHarness(t *testing.T, w *fakeWire) *Harness {
	t.Helper()
	h, err := New(w, "intake-agent")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return h
}

func TestNewNeedsAWire(t *testing.T) {
	if _, err := New(nil, "a"); err == nil {
		t.Fatal("want an error")
	}
}

func TestToolsUsesSearchToolsForMCP(t *testing.T) {
	w := &fakeWire{toolResp: &harnesspb.CallToolProtoResponse{OutputJson: []byte(
		`{"candidates":[{"id":"mcp:wiz:list","connector":"wiz","tool":"list"},{"id":"native:x","tool":"x"}]}`)}}
	tools, err := newHarness(t, w).Tools(context.Background())
	if err != nil {
		t.Fatalf("tools: %v", err)
	}
	if len(tools) != 1 || tools[0] != (intake.Tool{Connector: "wiz", Name: "list"}) {
		t.Fatalf("tools = %v", tools)
	}
	if w.tool[0].GetName() != "search_tools" || !strings.Contains(string(w.tool[0].GetInputJson()), `"mcp"`) {
		t.Fatalf("request = %v", w.tool[0])
	}
}

func TestInvokeSendsTheCanonicalIDAndReturnsTheCallID(t *testing.T) {
	w := &fakeWire{toolResp: &harnesspb.CallToolProtoResponse{OutputJson: []byte(`{"result":[1,2]}`), ToolCallId: "call-7"}}
	c, err := newHarness(t, w).Invoke(context.Background(), "wiz", "list", map[string]any{"a": 1})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if string(c.JSON) != "[1,2]" || c.ID != "call-7" {
		t.Fatalf("call = %+v", c)
	}
	var in struct {
		ID   string
		Args map[string]any
	}
	if err := json.Unmarshal(w.tool[0].GetInputJson(), &in); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if w.tool[0].GetName() != "invoke_tool" || in.ID != "mcp:wiz:list" || in.Args["a"] != float64(1) {
		t.Fatalf("request = %s", w.tool[0].GetInputJson())
	}
}

func TestInvokeKeepsTheCallIDOnARefusal(t *testing.T) {
	w := &fakeWire{toolResp: &harnesspb.CallToolProtoResponse{
		ToolCallId: "call-8",
		Error:      &harnesspb.HarnessError{Code: commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, Message: "denied"},
	}}
	c, err := newHarness(t, w).Invoke(context.Background(), "wiz", "list", nil)
	if err == nil || !strings.Contains(err.Error(), "denied") || c.ID != "call-8" {
		t.Fatalf("call=%+v err=%v", c, err)
	}
	w.err = errWire
	if _, err := newHarness(t, w).Tools(context.Background()); !errors.Is(err, errWire) {
		t.Fatalf("err = %v", err)
	}
}

func TestRaiseFlawSubmitsOneFindingWithAStableKey(t *testing.T) {
	w := &fakeWire{}
	h := newHarness(t, w)
	ho := intake.Handoff{Connector: "wiz", Tool: "list", Class: recipe.Cloud, CallID: "call-1",
		Item: recipe.Item{ID: "r-1", Cursor: "1", Title: "Open bucket", Description: "d", Severity: "HIGH"}}
	for range 2 {
		if err := h.RaiseFlaw(context.Background(), ho); err != nil {
			t.Fatalf("raise: %v", err)
		}
	}
	a, b := w.findings[0], w.findings[1]
	if a.GetIdempotencyKey() == "" || a.GetIdempotencyKey() != b.GetIdempotencyKey() {
		t.Fatalf("keys %q and %q must be equal and not empty", a.GetIdempotencyKey(), b.GetIdempotencyKey())
	}
	if len(a.GetIdempotencyKey()) > 128 {
		t.Fatal("the key is longer than the daemon accepts")
	}
	if len(a.GetToolCallIds()) != 1 || a.GetToolCallIds()[0] != "call-1" {
		t.Fatalf("the finding must cite the call: %v", a.GetToolCallIds())
	}
	tags := strings.Join(a.GetFinding().GetTags(), ",")
	if !strings.Contains(tags, "intake:connector=wiz") || !strings.Contains(tags, "intake:result=r-1") {
		t.Fatalf("tags = %s", tags)
	}
	if a.GetFinding().GetTitle() != "Open bucket" || a.GetFinding().GetCategory() != "cloud" {
		t.Fatalf("finding = %v", a.GetFinding())
	}
	if len(w.observed) != 0 {
		t.Fatal("a flaw must write no Alert")
	}
}

func TestResultKeyIsPerConnectorAndResult(t *testing.T) {
	if ResultKey("a", "1") == ResultKey("b", "1") || ResultKey("a", "1") == ResultKey("a", "2") {
		t.Fatal("the key must differ by connector and by result")
	}
	if ResultKey("ab", "c") == ResultKey("a", "bc") {
		t.Fatal("the key must not join the two parts by plain concatenation")
	}
}

func TestRaiseAlertObservesAnAlertAndRaisesNoFinding(t *testing.T) {
	w := &fakeWire{}
	ho := intake.Handoff{Connector: "sentinel", Tool: "ListAlerts", Class: recipe.SIEM, CallID: "c",
		Item: recipe.Item{ID: "al-1", Cursor: "1", Title: "Impossible travel", Severity: "high"}}
	if err := newHarness(t, w).RaiseAlert(context.Background(), ho); err != nil {
		t.Fatalf("raise: %v", err)
	}
	if len(w.findings) != 0 {
		t.Fatal("an alert must never be a finding")
	}
	e := w.observed[0].GetLifecycleEntity()
	if e.GetLabel() != "Alert" || e.GetIdProperties()["connector"] != "sentinel" || e.GetIdProperties()["result_id"] != "al-1" {
		t.Fatalf("entity = %v", e)
	}
	if len(e.GetIdProperties()) != 2 {
		t.Fatal("the identity is the connector and the result id, and nothing else")
	}
}

func TestRefusalsSurface(t *testing.T) {
	w := &fakeWire{respErr: &harnesspb.HarnessError{Message: "no"}}
	h := newHarness(t, w)
	ho := intake.Handoff{Connector: "c", Class: recipe.Scanner, Item: recipe.Item{ID: "1"}}
	if err := h.RaiseFlaw(context.Background(), ho); err == nil {
		t.Error("a refused finding must fail")
	}
	if err := h.RaiseAlert(context.Background(), ho); err == nil {
		t.Error("a refused alert must fail")
	}
	if err := h.Save(context.Background(), "c", recipe.Marker{Cursor: "1"}); err == nil {
		t.Error("a refused marker must fail")
	}
	w.respErr, w.err = nil, errWire
	if err := h.RaiseFlaw(context.Background(), ho); !errors.Is(err, errWire) {
		t.Errorf("err = %v", err)
	}
}

func TestSaveAndLoadMarker(t *testing.T) {
	w := &fakeWire{}
	h := newHarness(t, w)
	m := recipe.Marker{Cursor: "2026-11-20T10:00:00Z", AtCursor: []string{"a", "b"}}
	if err := h.Save(context.Background(), "wiz", m); err != nil {
		t.Fatalf("save: %v", err)
	}
	mem := w.observed[0].GetMemory()
	if mem.GetKind() != MarkerKind || mem.GetSourceRef() != "wiz" {
		t.Fatalf("memory = %v", mem)
	}

	node := func(conn, text string, at int64) *graphragpb.QueryResult {
		return &graphragpb.QueryResult{Node: &graphragpb.GraphNode{
			Content: text, UpdatedAt: at,
			Properties: map[string]*graphragpb.Value{"source_ref": {Kind: &graphragpb.Value_StringValue{StringValue: conn}}},
		}}
	}
	w.query = &harnesspb.QueryNodesResponse{Results: []*graphragpb.QueryResult{
		node("wiz", mem.GetText(), 20),
		node("wiz", `{"cursor":"old"}`, 10),
		node("tenable", `not json`, 30),
	}}
	got, err := h.Load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 || got["wiz"].Cursor != m.Cursor || len(got["wiz"].AtCursor) != 2 {
		t.Fatalf("markers = %+v", got)
	}
}

func TestSeverity(t *testing.T) {
	for in, want := range map[string]string{"CRITICAL": "critical", "High": "high", "medium": "medium", "low": "low", "": "info", "x": "info"} {
		if string(severity(in)) != want {
			t.Errorf("severity(%q) = %s, want %s", in, severity(in), want)
		}
	}
}
