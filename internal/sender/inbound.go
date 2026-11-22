// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sender

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"

	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

// The Go SDK client (a2ainbound) builds the message itself. It sends one text
// part and an optional target list, and it sets no message id and no metadata.
// The sender needs a data part, a message id and metadata, so it uses this thin
// client over the same endpoint. SDK NEEDS: a SendMessage in a2ainbound that
// takes a whole message. Then this file goes away.

// pathPrefix is the path prefix of the inbound endpoint of Gibson.
const pathPrefix = "/a2a/inbound/"

// agentPattern is a DNS label. The daemon refuses each other agent name.
var agentPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// ErrNoGrant means that the signer gave no grant. No byte went to Gibson.
var ErrNoGrant = errors.New("sender: no grant for the request")

// PathSigner signs the Capability Grant JWT of one request, bound to its path.
// *capabilitygrant.Client is a PathSigner.
type PathSigner interface {
	SignPath(path string) (string, error)
}

// Inbound sends messages to the inbound A2A endpoint of Gibson.
type Inbound struct {
	base string
	http *http.Client
}

// NewInbound returns an Inbound. baseURL is the https origin of the platform.
// transport is optional and is the base transport of each call.
func NewInbound(baseURL string, signer PathSigner, transport http.RoundTripper) (*Inbound, error) {
	u, err := capabilitygrant.ParsePlatformURL(baseURL)
	if err != nil {
		return nil, fmt.Errorf("sender: %w", err)
	}
	if strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("sender: the base URL %q must be an origin with no path and no query", baseURL)
	}
	if signer == nil {
		return nil, errors.New("sender: a signer is required")
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	hc := &http.Client{
		Transport: &signingTransport{next: transport, signer: signer},
		// A redirect would make the client sign a token for a URL that nobody named.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Inbound{base: u.Scheme + "://" + u.Host, http: hc}, nil
}

// signingTransport adds a new grant, bound to the path, to each request.
type signingTransport struct {
	next   http.RoundTripper
	signer PathSigner
}

func (t *signingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.signer.SignPath(req.URL.RequestURI())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoGrant, err)
	}
	out := req.Clone(req.Context())
	out.Header.Set(capabilitygrant.MetadataHeaderCapabilityGrant, token)
	resp, err := t.next.RoundTrip(out)
	if err != nil {
		return nil, fmt.Errorf("round trip: %w", err)
	}
	return resp, nil
}

// SendMessage sends one whole message to a published agent and returns the Task
// of the mission that it started.
func (c *Inbound) SendMessage(ctx context.Context, agent string, msg *a2a.Message) (*a2a.Task, error) {
	if !agentPattern.MatchString(agent) {
		return nil, fmt.Errorf("sender: the agent name %q is not a DNS label", agent)
	}
	endpoint := c.base + pathPrefix + agent
	client, err := a2aclient.NewFromEndpoints(ctx,
		[]*a2a.AgentInterface{a2a.NewAgentInterface(endpoint, a2a.TransportProtocolJSONRPC)},
		a2aclient.WithConfig(a2aclient.Config{PreferredTransports: []a2a.TransportProtocol{a2a.TransportProtocolJSONRPC}}),
		a2aclient.WithJSONRPCTransport(c.http),
	)
	if err != nil {
		return nil, fmt.Errorf("sender: create the a2a client: %w", err)
	}
	defer func() { _ = client.Destroy() }()
	res, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: msg})
	if err != nil {
		return nil, fmt.Errorf("sender: send a message to %s: %w", agent, err)
	}
	task, ok := res.(*a2a.Task)
	if !ok {
		return nil, fmt.Errorf("sender: send a message to %s: the answer is a %T and not a task", agent, res)
	}
	return task, nil
}
