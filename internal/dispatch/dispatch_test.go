// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dispatch

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) Getenv { return func(k string) string { return m[k] } }

func TestFrom(t *testing.T) {
	ok := map[string]string{EnvInstanceMode: "member", EnvGrant: "g", EnvCallbackEndpoint: "cb:443"}
	with := func(k, v string) map[string]string {
		c := map[string]string{}
		for a, b := range ok {
			c[a] = b
		}
		c[k] = v
		return c
	}
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
		want    time.Duration
	}{
		{"default interval", ok, "", DefaultInterval},
		{"set interval", with(EnvInterval, "90s"), "", 90 * time.Second},
		{"one shot refused", with(EnvInstanceMode, "oneshot"), EnvInstanceMode, 0},
		{"no mode refused", with(EnvInstanceMode, ""), EnvInstanceMode, 0},
		{"no grant", with(EnvGrant, ""), EnvGrant, 0},
		{"no endpoint", with(EnvCallbackEndpoint, ""), EnvCallbackEndpoint, 0},
		{"bad interval", with(EnvInterval, "soon"), EnvInterval, 0},
		{"negative interval", with(EnvInterval, "-1m"), EnvInterval, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := From(env(tc.env))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to name %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if m.Interval != tc.want || m.Grant != "g" {
				t.Fatalf("got %+v", m)
			}
		})
	}
	if _, err := From(nil); err == nil {
		t.Fatal("a nil reader must fail")
	}
}
