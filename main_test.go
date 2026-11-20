// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"strings"
	"testing"
)

// TestRunRefusesALaunchWithNoContract: the agent must fail at start and not dial
// with no grant.
func TestRunRefusesALaunchWithNoContract(t *testing.T) {
	for _, k := range []string{"GIBSON_CG_JWT", "GIBSON_CALLBACK_ENDPOINT", "GIBSON_INSTANCE_MODE"} {
		t.Setenv(k, "")
	}
	err := run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "launch contract") {
		t.Fatalf("err = %v", err)
	}
}
