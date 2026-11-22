# AGENTS.md — intake-agent

This directory is a Gibson agent. It is an always-on bank member (ADR-0119).
This file is the contract. If this file and the code disagree, the code wins.

## What it does

The agent reads the security tools of the buyer through connectors.
Each pass does these steps for each enabled connector that has a recipe.

1. List the tools of the enabled connectors with `search_tools`.
2. Call the read tool of the recipe with `invoke_tool`, from the marker of the connector.
3. Hand each result to the daemon with the connector id and the result id.
4. Move the marker of the connector after each result that the daemon accepted.

The class of the recipe selects the path. A result of class `scanner` or `cloud`
is a flaw and becomes a finding. A result of class `siem`, `edr` or `identity`
is an alert and becomes an `Alert` node, never a finding.

## How the code is laid out

| Path | What it holds |
|---|---|
| `main.go` | The entry point. It reads the launch contract, dials the harness, runs the loop. |
| `internal/dispatch` | The launch contract of a member. |
| `internal/recipe` | The recipe type and the shipped recipes. One file for each connector. |
| `internal/intake` | The pass and the loop. It uses two seams: `Daemon` and `Markers`. |
| `internal/daemon` | The one place that calls the harness callback service. |
| `internal/mirror` | The ticket mirror loop (gibson#1450). It uses a `Source` and one `Adapter` for each ticket connector. |
| `internal/pager` | The pager loop (gibson#1501). It uses a `Source` and one `Adapter` for each paging connector. |
| `internal/sender` | The webhook sender (gibson#1451). It is a second binary at `cmd/webhook-sender`. |

To add a connector, add `internal/recipe/<connector>.go` and list it in
`recipes.go`. A recipe needs a vendor source, a tool name, its arguments and its
result shape. Do not add a recipe for a tool that nobody verified in a vendor
document.

The mirror and the pager reach a connector only through `intake.Caller`. They
keep no state outside the ticket tool and the paging tool. A tenant with no
ticket connector or no paging connector gets no error. The loop logs it once.

## Identity of a result

A second read of one result must change the same finding or the same Alert.

- An Alert has the identity `connector` and `result_id` (`LifecycleEntityObservation`).
- A finding gets the idempotency key `ResultKey(connector, result id)`.
  The finding id is stable only on a daemon that derives it from that key.
  See README.md, "Open points".

## Do not

- Hold a vendor credential. The daemon is the one caller of a connector.
- Open a network connection other than the harness callback. The catalog entry has no egress.
- Call the daemon outside `internal/daemon`.
- Add a second path to read or write the marker.
- Use `replace` directives in `go.mod`, or add a `go.work`.
