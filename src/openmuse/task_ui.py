"""Escaped persistent task-thread UI."""

import html

from .tasks import TaskRecord


def render_task_thread(task: TaskRecord, events: list[dict[str, object]]) -> str:
    items: list[str] = []
    for event in events:
        data = event["data"]
        body = data.get("body", data) if isinstance(data, dict) else data
        items.append(
            f'<li data-sequence="{html.escape(str(event["sequence"]))}"><strong>{html.escape(str(event["kind"]))}</strong>: {html.escape(str(body))}</li>'
        )
    return f'<main><h1>{html.escape(task.goal)}</h1><p>Status: {html.escape(task.status)} · Step {task.step}/{task.max_steps}</p><ol>{"".join(items)}</ol><form method="post"><label>Side chat <textarea name="body"></textarea></label><button>Post</button></form></main>'
