# intake-agent

An always-on Gibson agent. It reads the security tools of the buyer through
connectors. It turns each flaw into a finding and each alert into an `Alert`
node. It changes nothing in the tools of the buyer.

It is built with the ADK, the same way as `cve-triage`. The agent contract is in
[AGENTS.md](./AGENTS.md).

## How it runs

The agent is a bank member (ADR-0119). The catalog manifest in gibson declares
`memberCommand: /intake-agent`. The agent holds no vendor credential and has no
egress. It reaches only the harness callback service. The daemon is the one
caller of a connector.

The launch contract of a member is these variables:

| Variable | Carries |
|---|---|
| `GIBSON_INSTANCE_MODE` | Must be `member`. |
| `GIBSON_CG_JWT` | The grant of the run. |
| `GIBSON_CALLBACK_ENDPOINT` | The harness callback service to dial. |
| `GIBSON_MISSION_ID`, `GIBSON_MISSION_RUN_ID`, `GIBSON_AGENT_RUN_ID` | The scope of the run. |
| `INTAKE_INTERVAL` | The time between two reads. The manifest sets it. The default is `5m`. |

## One pass

1. `search_tools` lists the tools of the enabled connectors.
2. For each connector with a recipe, `invoke_tool` calls the read tool of the recipe.
3. The agent skips each result that is behind the marker of the connector.
4. The agent skips and counts each result with no id or no cursor.
5. The agent hands each other result to the daemon, at most 1000 for each call, oldest first. A flaw goes to `SubmitFinding`. An alert goes to `Observe` as an `Alert` entity.
6. After each result that the daemon accepted, the agent saves the marker of the connector.

A failure in one connector does not stop the others. The marker never moves past
a result that the daemon refused. The next pass reads the results over the limit.
When the daemon refuses the grant (`Unauthenticated`, for example an expired
grant), the agent stops with an error.

## The agent does not start yet

The agent refuses to start, with an error, for two reasons:

- No recipe ships (see below). An agent with no recipe reads nothing.
- No marker store exists (see "Open points").

## The recipes

One recipe is one file in `internal/recipe`, named after the catalog id of the
connector. A recipe states the tool, the arguments, the parse of the result and
the vendor document. A recipe without an https vendor source does not load.

**No recipe ships yet.** A recipe needs the tool name and the result shape from
a vendor document. For each connector below, the vendor document names the tool.
No document that was read gives the result shape (the field of the result id and
the field of the cursor). A guess would read wrong data, so the recipe is left out.

| Connector (class) | Verified read tool | Vendor document | Missing |
|---|---|---|---|
| `microsoft-defender-endpoint` (edr) | `ListAlerts` with `createdAfter`, `skip`, `top`. `ListIncidents` with the same. | https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool | The result fields. Run `ListAlerts` once and read the id and time fields. |
| `microsoft-sentinel` (siem) | `ListIncidents` and `ListAlerts` are on the triage server of the `microsoft-defender-endpoint` entry. The data exploration server of this entry has no alert tool in the survey. | same | A tool and the result fields. |
| `crowdstrike-falcon` (edr) | `falcon_search_detections`, with an FQL `filter` parameter. | https://developer.crowdstrike.com/falcon-mcp/modules/detections/ | The other parameters and the result fields. The page says only that a record holds "process context, device info, tactic/technique details". |
| `tenable` (scanner) | `workbenches_list_vulnerabilities`, `workbenches_list_assets_with_vulnerabilities`. | https://docs.tenable.com/vulnerability-management/Content/getting-started/hexa-AI-MCP.htm | The parameter names and the result fields. The page gives neither. |
| `wiz` (scanner) | None. | https://mcp.app.wiz.io/.well-known/oauth-protected-resource | The tool list. The Wiz documents need a login. |
| `microsoft-entra` (identity) | `microsoft_graph_get`, a generic Graph read. | https://learn.microsoft.com/en-us/graph/mcp-server/overview | The Graph resource that holds sign-in risk events, and the result shape. |
| `aws-security-hub` (cloud) | None. The AWS MCP server has `aws___run_script` and no tool for findings. | https://docs.aws.amazon.com/agent-toolkit/latest/userguide/getting-started-aws-mcp-server.html | A recipe would be a script. That is not a read recipe. |

The connectors `datadog` (observability), `jira` (ticket), `pagerduty` (paging)
and `aws-systems-manager` (patch) are not in the five classes of intake.

## Open points

These points need a change that is not in this repository.

- **A member has no grant that can call a tool.** The base grant of a member
  reaches no tenant tool, no finding and no connector. Only a turn grant, from a
  sender, does. An always-on loop has no turn. Until the daemon gives a member a
  grant for its own loop, the agent uses the grant that it is launched with, and
  that grant must allow `CallToolProto`, `SubmitFinding` and `Observe`.
- **The Go SDK has no wrapper for `PullJob`, `SubscribeInput` or the member
  heartbeat.** The agent does not pull jobs. The reconciler of the bank marks a
  member dead when its heartbeat stops.
- **The tool class comes from the recipe.** On the gibson branch
  `integration/blue-team`, `search_tools` returns `tool_class` for each
  candidate. The agent does not read it yet, because no recipe ships to check
  it against.
- **The finding identity is stable only on `integration/blue-team`.** The agent
  sends the idempotency key `ResultKey(connector, result id)`. On that branch the
  daemon derives the finding id from the tenant, the agent name and the key, and
  writes the finding with an upsert on that id (gibson#1448). On gibson `main`
  each submit gets a new finding id. The upsert also writes the status that the
  agent sends, which is `open`. A second read of a result can so move a finding
  in `fixing` back to `open`.
- **No marker store.** The marker must have one author and one order. A query of
  memory nodes has neither: it has no order and no author filter, so the newest
  marker can drop out, and any writer in the tenant can forge one. The daemon
  needs a Timeline marker event that it writes for the identity of this agent
  only, and a read of the last marker of one connector. The gibson branch
  `integration/blue-team` has neither, and the SDK has no client call for them.
  Until both exist, `daemon.NewMarkers` refuses and the agent does not start.
- **The interval is not a mission constraint.** A member has no mission. The
  interval is the variable `INTAKE_INTERVAL` of the manifest.
- **`Alert` is not in the Taxonomy of `origin/main`.** It is on the branch
  `epic/incident-response`. Before that merges, an `Alert` lands as an
  `Observation` with its residue (ADR-0112).

## Develop

| Verb | What it does |
|---|---|
| `make build` | Compile the binary. |
| `make test` | Run the unit tests. |
| `make check` | Run the guards that CI runs on a pull request. |
