# Product foundation
The first vertical slice now includes a channel adapter, SQLite task checkpoints, envelope-encrypted local vault, browser-worker policy envelope, and server-rendered approval diff. These are composable foundations, not a production hosted service yet.

Next integration order: connect WebChannel to Agent, run browser jobs in a separate container, persist approvals/tasks in a server DB, expose approval pages over authenticated web routes, then add a read-only calendar connector.
