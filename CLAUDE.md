# CLAUDE.md — intake-agent

Read [AGENTS.md](./AGENTS.md) first. It holds the contract.

| Verb | What it does |
|---|---|
| `make build` | Compile the binary |
| `make test` | Run unit tests |
| `make check` | Run the guards that CI runs on a pull request |

Do not add `replace` directives to `go.mod`. Do not add a `go.work`.
Do not add a recipe without a vendor source.
