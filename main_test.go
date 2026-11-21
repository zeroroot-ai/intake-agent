// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/intake-agent/internal/recipe"
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

// TestRunRefusesToStartWithNoRecipe: with no recipe the agent stops before it
// dials, so it never runs as an empty loop.
func TestRunRefusesToStartWithNoRecipe(t *testing.T) {
	if len(recipe.All()) != 0 {
		t.Skip("a recipe ships")
	}
	t.Setenv("GIBSON_INSTANCE_MODE", "member")
	t.Setenv("GIBSON_CG_JWT", "grant")
	t.Setenv("GIBSON_CALLBACK_ENDPOINT", "127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := run(ctx); !errors.Is(err, recipe.ErrNoRecipes) {
		t.Fatalf("err = %v", err)
	}
}
