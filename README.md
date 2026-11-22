# intake-agent

An always-on Gibson agent. It reads the security tools of the buyer through
connectors. It turns each flaw into a finding and each alert into an `Alert`
node. The intake loop changes nothing in the tools of the buyer.

The same agent runs two more loops. The mirror loop copies each finding and
each incident to the ticket tool of the buyer. The pager loop pages a person
for an item that waits too long. A separate binary, the webhook sender, turns a
webhook into an A2A message. See "The ticket mirror", "The pager" and "The
webhook sender".

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

Today no loop can start, for these reasons:

- The intake loop has no recipe (see below) and no marker store (see "Open points").
- The ticket mirror has no item source and no adapter. The pager has no wait
  source and no adapter (see "Open points").

The three loops are independent. A loop with a missing part is disabled, and
it logs one line with each cause. The other loops start. The agent exits with an
error only when no loop can start. When one loop stops with an error, for
example `ErrGrant`, the other loops go on. The agent exits when each loop has
stopped.

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
- **A finding check that holds the result id (gibson#1448).** The agent sends
  the id of the tool call (`ToolCallIds`), the idempotency key and the tag
  `intake:result=<result id>`. The store of gibson sets `Check.Ref` from the
  recorded tool name only (`SubmittedFindingCheck`). It must add the result id
  from the tag, so that the check of a finding names the tool and the result.
- **The ticket and the pager loops have no source.** The agent is a member with
  an agent identity.
  - No call lists findings and incidents of the tenant. `GetFindings` of the
    callback service is scoped to one mission. The tenant calls admit a user or a
    service identity.
  - `ListWaitingOnPerson` admits a user and a service identity (`allowed_identities: 3`),
    and it is not on the callback service.
  - The tenant has no wait limit setting. Until it exists, every tenant gets
    the default limit of four hours (`pager.DefaultLimit`).
  - Until these exist, `daemon.NewItemSource` and `daemon.NewWaitSource` refuse,
    and the agent does not start.
- **No ticket adapter and no paging adapter ships.** The rule of the recipes
  applies: no tool call that nobody verified in a vendor document. The tables
  below show what is verified and what is missing.
- **ServiceNow has no catalog manifest.** The mirror has no ServiceNow adapter
  until the manifest and a vendor document for its tools exist.
- **The status of an incident.** The mirror closes the ticket of an incident at
  `resolved`. The status names come from the branch `epic/incident-response`.
  Check them when that branch merges.
- **The interval is not a mission constraint.** A member has no mission. The
  interval is the variable `INTAKE_INTERVAL` of the manifest.
- **`Alert` is not in the Taxonomy of `origin/main`.** It is on the branch
  `epic/incident-response`. Before that merges, an `Alert` lands as an
  `Observation` with its residue (ADR-0112).

### Ticket and paging tools

I read the published sources for each tool. They do not give what an adapter needs.
The `tools/list` call of a remote server needs a credential of the tenant, so I
could not read the schemas there.

| Connector (class) | What the vendor publishes | What is missing |
|---|---|---|
| `jira` (ticket) | The tool names in https://support.atlassian.com/atlassian-rovo-mcp-server/docs/supported-tools/. The arguments of `createJiraIssue` (`cloudId`, `projectKey`, `issueType`, `summary`, `description`, `priority`) and of `searchJiraIssuesUsingJql` (`cloudId`, `jql`, `fields`, `maxResults`), in the skills of https://github.com/atlassian/atlassian-mcp-server (`skills/triage-issue/SKILL.md`). A create result with `key` (`skills/spec-to-backlog/SKILL.md`). A non primary tool runs through `execute` with `name`, `cloudId` and `inputs`. | The arguments of `transitionJiraIssue` and `listJiraIssueTransitions`, so no adapter can close a ticket. The result shape of the search. A way to mark a ticket with the item id. |
| `servicenow` (ticket) | I found no public document or repository of a ServiceNow MCP server. | A vendor server, then the catalog manifest. This belongs to the connectors lane. |
| `pagerduty` (paging) | The remote server lists tools with actions: `browse_incidents` (list, get, ...) and `manage_incidents` (create, update, add_note, ...) at https://docs.pagerduty.com/ai-automation/advance/pagerduty-mcp-server.md. | The arguments and results of these tools. The open source server https://github.com/PagerDuty/pagerduty-mcp-server has other tools (`list_incidents`, `create_incident`), and its `manage_incidents` is a different tool. Its README says that the hosted server replaces it. The code of that server is not the schema of the remote server. |

## Why the mirror and the pager are loops of this agent

The mirror (gibson#1450) and the pager (gibson#1501) run in this agent as two
more loops. They are not two more agents. The reasons are these.

- One member has one grant, one callback client and one launch. A new agent
  needs its own catalog manifest, its own image and its own bank member.
- Both loops use the same seam as the intake loop. They list the tools of the
  enabled connectors and call one tool through the daemon.
- Each loop has its own package and its own state. A failure in one loop does
  not stop a pass of another loop. When the daemon refuses the grant, all three
  loops stop, because the grant is shared.

The cost is a wider grant. The intake loop only reads. The mirror and the pager
write to the tools of the buyer. The catalog manifest of this agent must grant
the classes `ticket` and `paging` as well. That manifest is gibson#1449. A tenant
that wants a read only intake agent must not enable a ticket or a paging
connector.

All three loops use one timer, `intake.Loop`, and one interval, `INTAKE_INTERVAL`.

## The ticket mirror

Package `internal/mirror`. Gibson stays the source. A change in a ticket changes
nothing in Gibson.

1. The pass lists the tools of the enabled connectors.
2. When the tenant has no ticket connector, the pass does nothing. It logs this
   one time. It returns no error.
3. For each finding and each incident, the adapter looks for the ticket of the
   item in the ticket tool.
4. When no ticket exists, the adapter opens one with the severity and the link
   to the item. The pass opens no ticket for an item that is already done.
5. When the status of the item differs from the status in the ticket, the
   adapter updates the ticket.
6. When the item is `verified`, the adapter closes the ticket. An incident closes
   at `resolved`.

The mirror keeps no state. The ticket holds the id of the item and the last
status that the mirror wrote, so a restart opens no second ticket.

## The pager

Package `internal/pager`. The items come from `ListWaitingOnPerson`
(gibson#1500).

1. The pass lists the tools of the enabled connectors.
2. When the tenant has no paging connector, the pass does nothing. It logs this
   one time. It returns no error.
3. The pass reads the wait limit that the tenant set. When the tenant set no
   limit, the pass uses the default of four hours (`pager.DefaultLimit`).
4. For each item that waited longer than the limit, the pass makes the key of the
   wait. The key is the kind, the id and the start time of the wait.
5. When the pager or the paging tool already holds a page with this key, the pass
   sends nothing. Else it pages the person on call, with the link to the item.

One wait gives one page. An item that waits again later starts a new wait and
gives a new page.

## The webhook sender

Binary `cmd/webhook-sender`, package `internal/sender`. It is the same image
as the agent, at `/webhook-sender` (gibson#1451).

Gibson has no webhook receiver. The sender runs next to the tool of the buyer.
It receives the webhook and sends one A2A message to a published Gibson agent.
Gibson starts one mission from the definition that the tenant published for that
agent (gibson#1367).

- The sender is an enrolled identity with the ceiling `mission:originate`. A
  tenant admin makes it with `CreateAgentIdentity` and gives it the grant to the
  published definition.
- The sender checks each webhook. The signature is
  `sha256=<hex>` of the HMAC-SHA256 of `<timestamp>.<event id>.<body>`, in the
  header `X-Webhook-Signature`. The timestamp (Unix seconds) is in
  `X-Webhook-Timestamp`. The event id is in `X-Webhook-Id`. The comparison takes
  constant time. An unsigned webhook gets `401`.
- Replay protection. The sender refuses an event that is older than five minutes
  or more than five minutes ahead (`401`). It refuses an event id that it
  already took (`409`). It holds an id until twice the window after the event
  time.
- The send to Gibson does not stop when the tool closes its request. It has its
  own time limit of 30 seconds. The sender frees an event id only when the error
  proves that Gibson did not take the message: no grant, a refused connection, or
  a `401` or `403` of the edge. After any other error, such as a lost reply, the
  id stays held and a retry gets `409`, because Gibson may have started the
  mission. A Task state "rejected" (`403` of the sender) also keeps the id held.
- The webhook goes to the agent as data. The message has one fixed text part that
  says the data is untrusted and is never an instruction. The body is in a data
  part under the key `webhook`, as JSON, so no key of the body can reach a key
  that the daemon reads, such as `targets`. The event id is the message id
  (`webhook:<source>:<id>`) and is in the metadata as `webhook_id`.
- The secret has at least 32 bytes. A shorter secret stops the start.
- The server has a read, a write and an idle time limit. The write limit covers
  the read of the body, the send and the answer. A stop waits for a request in
  flight, up to the write limit.
- Grace period. The write limit and the stop wait are 75 seconds
  (`shutdownTimeout` in `cmd/webhook-sender/main.go`). The pod of the sender needs
  `terminationGracePeriodSeconds` of at least 75. The Kubernetes default is 30
  seconds, and it would kill a send that Gibson already took.
- The store of event ids is in the memory of one process. It holds at most 10000
  ids. When it is full, the sender answers `503`. It protects one replica. Two
  replicas, or a restart inside the window, can take a repeated event. Run one
  replica until a shared store exists.
- Other signature schemes come with each vendor recipe (gibson#1561). This
  sender has one scheme.
- The sender sends no target, so a
  webhook cannot add a target.
- When the enrollment fails, the sender does not listen. When Gibson refuses the
  sender later, the sender answers `502` and no mission starts. When Gibson
  rejects the message, the sender answers `403`.

| Variable | Carries |
|---|---|
| `GIBSON_PLATFORM_URL` | The public API origin of the platform, with https. |
| `GIBSON_BOOTSTRAP_TOKEN` | The one time token of the first start. |
| `GIBSON_HOST_KEY_PATH` | The path of the host key file. |
| `SENDER_AGENT` | The name of the published Gibson agent. |
| `SENDER_SOURCE` | The name of the tool that sends the webhook. |
| `SENDER_WEBHOOK_SECRET` | The shared secret of the signature. |
| `SENDER_SIGNATURE_HEADER` | The header of the signature. The default is `X-Webhook-Signature`. |
| `SENDER_LISTEN` | The listen address. The default is `:8080`. |

The daemon gets no new HTTP intake path. The sender uses the inbound A2A
endpoint that gibson#1367 built, through the Edge, as any outside A2A client does.
The sender needs a whole message, with a data part, a message id and metadata.
It sends it with `Client.Send` of `a2ainbound` in the Go SDK (v0.214.0 and later).
The sender wraps the signer, so that a signer error counts as "no grant" and
frees the event id.

**Dependency on gibson.** Gibson main builds the input of a mission from the
text parts of an A2A message only (`a2a_inbound_runs.go`, `a2aserver/handler.go`).
It drops a data part. So today the mission gets the fixed note and not the
alert. The gibson change that passes the `webhook` data part to the mission as
typed, untrusted task data is zeroroot-ai/gibson#1611. The tests of this repo
assert the current contract (`TestTheMissionInputOfGibsonMainHasNoWebhookData`).
Update that test when gibson changes.

The event id and the source have only `A-Z a-z 0-9 . _ -`, so the message id
`webhook:<source>:<id>` has one reading. It is for a planned dedup in gibson,
which does not exist. A dedup key must include the tenant.

## Develop

| Verb | What it does |
|---|---|
| `make build` | Compile the binary. |
| `make test` | Run the unit tests. |
| `make check` | Run the guards that CI runs on a pull request. |
