"""Render a human-readable approval diff outside planner-controlled text."""

import html

from .models import Action


def render_approval(action: Action, identity: str, destination: str, cost: str | None = None) -> str:
    rows = "".join(
        f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>"
        for k, v in sorted(action.arguments.items())
    )
    cost_line = f"<p><strong>Cost:</strong> {html.escape(cost)}</p>" if cost else ""
    return f"<main><h1>Approve action</h1><p><strong>Identity:</strong> {html.escape(identity)}</p><p><strong>Destination:</strong> {html.escape(destination)}</p>{cost_line}<p><strong>Tool:</strong> {html.escape(action.tool)}</p><table>{rows}</table><p>Approval expires and can be used once.</p></main>"
