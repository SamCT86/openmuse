# Public API compatibility

The names exported from `openmuse.__all__` are the supported Python API. They follow semantic versioning: breaking changes require a major release, and deprecated names remain through the next major release. Deep imports from `openmuse.*` are implementation details unless separately documented.

OpenMuse is pre-1.0, so each release note calls out any unavoidable compatibility change explicitly.

## Extension author contract (alpha)

`Tool` is a structural protocol with `name`, `description`, `risk`,
`manifest()` and `run(**kwargs)`. The manifest must agree with those fields;
`schema` uses JSON Schema Draft 2020-12. `ManifestMixin` is a helper for
trusted host tools. The registry checks identity and snapshots the schema and
risk when the host registers an instance. Use `Agent([...], Policy(), path)` to
register trusted tools. Supported imports for this minimal protocol are
`from openmuse import Tool, ManifestMixin, Risk, Agent, Action, Policy`. The
connector exports are `Capability`, `ReadOnlyConnector`, `ScopeGrants`,
`connector_tools`; `WorkerTool` is the constrained read-only container adapter.

These Python extension APIs are for **trusted host code** only. A skill artifact
is data/instructions and cannot gain Python execution by being called a skill.
Do not register unreviewed Python plugins; the worker adapter has no effect
RPC and cannot safely implement untrusted write/represent/money plugins.
