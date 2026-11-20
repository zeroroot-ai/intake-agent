// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package dispatch reads the launch contract of a bank member.
//
// Gibson launches this image in member mode (ADR-0119) with the command
// `memberCommand` of the catalog manifest. A member gets no task. It gets a
// grant, the callback endpoint and the ids of its run. The names below are the
// launch contract. Gibson is the only writer of them.
package dispatch

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// The launch contract of a member.
const (
	EnvGrant            = "GIBSON_CG_JWT"
	EnvCallbackEndpoint = "GIBSON_CALLBACK_ENDPOINT"
	EnvInstanceMode     = "GIBSON_INSTANCE_MODE"
	EnvMissionID        = "GIBSON_MISSION_ID"
	EnvMissionRunID     = "GIBSON_MISSION_RUN_ID"
	EnvAgentRunID       = "GIBSON_AGENT_RUN_ID"
	// EnvInterval is the time between two reads of the connectors. The catalog
	// manifest sets it. See README.md for why it is not a mission constraint.
	EnvInterval = "INTAKE_INTERVAL"
)

// ModeMember is the value of EnvInstanceMode for a bank member.
const ModeMember = "member"

// DefaultInterval is the time between two reads when the manifest sets none.
const DefaultInterval = 5 * time.Minute

// Member is one launch.
type Member struct {
	Grant            string
	CallbackEndpoint string
	MissionID        string
	MissionRunID     string
	AgentRunID       string
	Interval         time.Duration
}

// Getenv reads one variable. Tests inject it.
type Getenv func(string) string

// FromEnv reads the launch contract from the process environment.
func FromEnv() (Member, error) { return From(os.Getenv) }

// From reads the launch contract from getenv. A missing grant fails the launch
// so that a run never dials with no credential.
func From(getenv Getenv) (Member, error) {
	if getenv == nil {
		return Member{}, errors.New("dispatch: no environment reader")
	}
	m := Member{
		Grant:            strings.TrimSpace(getenv(EnvGrant)),
		CallbackEndpoint: strings.TrimSpace(getenv(EnvCallbackEndpoint)),
		MissionID:        strings.TrimSpace(getenv(EnvMissionID)),
		MissionRunID:     strings.TrimSpace(getenv(EnvMissionRunID)),
		AgentRunID:       strings.TrimSpace(getenv(EnvAgentRunID)),
		Interval:         DefaultInterval,
	}
	if mode := strings.TrimSpace(getenv(EnvInstanceMode)); mode != ModeMember {
		return Member{}, fmt.Errorf("dispatch: %s is %q: this agent runs only as a bank member", EnvInstanceMode, mode)
	}
	if m.Grant == "" {
		return Member{}, fmt.Errorf("dispatch: %s is not set: the agent cannot run without its grant", EnvGrant)
	}
	if m.CallbackEndpoint == "" {
		return Member{}, fmt.Errorf("dispatch: %s is not set: there is nowhere to report to", EnvCallbackEndpoint)
	}
	if raw := strings.TrimSpace(getenv(EnvInterval)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return Member{}, fmt.Errorf("dispatch: %s is %q: it must be a positive duration such as 5m", EnvInterval, raw)
		}
		m.Interval = d
	}
	return m, nil
}
