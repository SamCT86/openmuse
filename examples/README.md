# OpenMuse examples

Every example runs locally. Start with the approval demo, then pick the boundary you want to inspect.

| Example | What it shows | Credentials | Command |
|---|---|---|---|
| [`approval_app.py`](approval_app.py) | Local UI for inspecting and approving or denying one exact persisted action | None | `python examples/approval_app.py` |
| [`e2e_demo.py`](e2e_demo.py) | Exact-action approval, a durable task, and a hash-chained audit | None | `python examples/e2e_demo.py` |
| [`verify_audit.py`](verify_audit.py) | Independent verification of the demo's audit chain and executed action | None | `python examples/verify_audit.py` |
| [`isolated_worker_demo.py`](isolated_worker_demo.py) | A JSON job in a fresh, resource-limited process | None | `python examples/isolated_worker_demo.py` |
| [`memory_demo.py`](memory_demo.py) | Curated memory with provenance, search, verification, edit, and forget | None | `python examples/memory_demo.py` |
| [`scheduler_demo.py`](scheduler_demo.py) | A persisted cron job claimed atomically by one worker | None | `python examples/scheduler_demo.py` |
| [`typed_tool.py`](typed_tool.py) | Agent-registered typed tool with closed bounded arguments and read-only risk | None | `python examples/typed_tool.py` |
| [`local_planner.py`](local_planner.py) | The smallest deterministic planner loop | None | `python examples/local_planner.py` |

The Google Calendar and Gmail connectors need host-managed OAuth credentials. Their deterministic, credential-free boundary examples live in [`tests/test_google_calendar_connector.py`](../tests/test_google_calendar_connector.py), [`tests/test_google_mail_connector.py`](../tests/test_google_mail_connector.py), and [`tests/test_google_oauth.py`](../tests/test_google_oauth.py). Do not use sensitive production accounts while OpenMuse is alpha.

`approval_app.py` binds to localhost and is a reference demo, not a production approval surface. Production hosts must add TLS, authenticated identity, CSRF protection, and secure cookies.
