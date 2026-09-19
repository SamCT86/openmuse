# Product foundation

The first vertical slice includes a channel adapter, SQLite task checkpoints, envelope-encrypted local vault, browser-worker policy envelope, and server-rendered approval diff. The WebChannel now drives the Agent end to end in the demo, scoped read-only Google Calendar and Gmail connectors have landed with managed OAuth, and `IsolatedWorker` runs jobs in a separate resource-limited OS process. These are composable foundations, not a production hosted service yet.

Next integration order: run browser jobs in a container or VM with network isolation on top of the process worker, persist approvals and tasks in a server database, and expose approval pages over authenticated web routes.
