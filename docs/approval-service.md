# Persistent approval service

`ApprovalService` stores the exact serialized action, identity, destination, expiry, and decision in SQLite. A host-authenticated session token binds the browser decision to the request and expiry. Decisions use an immediate transaction, expire fail-closed, and can be consumed once. An embedding web app should render the stored action through `render_approval`, use an authenticated session cookie, enforce HTTPS and CSRF protection, then call `decide`; planner text never supplies the decision.
