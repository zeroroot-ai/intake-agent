// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"

func markerQuery() *graphragpb.GraphQuery {
	return &graphragpb.GraphQuery{
		NodeTypes: []string{"Observation"},
		Filters:   map[string]string{"shape": "Memory", "kind": MarkerKind},
		TopK:      1000,
		Scope:     graphragpb.QueryScope_QUERY_SCOPE_GLOBAL,
	}
}
