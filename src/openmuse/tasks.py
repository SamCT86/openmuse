"""Durable task records and restart-safe checkpoints."""

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class TaskRecord:
    id: str
    goal: str
    status: str
    step: int
    max_steps: int
    checkpoint: dict[str, Any]


class TaskStore:
    def __init__(self, path: Path) -> None:
        self.db = sqlite3.connect(path)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY, goal TEXT, status TEXT, step INTEGER, max_steps INTEGER, checkpoint TEXT, updated_at TEXT)"
        )
        self.db.commit()

    def create(self, goal: str, max_steps: int = 8) -> TaskRecord:
        task = TaskRecord(uuid4().hex, goal, "pending", 0, max_steps, {})
        self._save(task)
        return task

    def get(self, task_id: str) -> TaskRecord | None:
        row = self.db.execute(
            "SELECT id,goal,status,step,max_steps,checkpoint FROM tasks WHERE id=?", (task_id,)
        ).fetchone()
        return TaskRecord(row[0], row[1], row[2], row[3], row[4], json.loads(row[5])) if row else None

    def checkpoint(self, task_id: str, step: int, data: dict[str, Any], status: str = "running") -> TaskRecord:
        task = self.get(task_id)
        if not task:
            raise KeyError(task_id)
        if step > task.max_steps:
            raise ValueError("step budget exceeded")
        updated = TaskRecord(task.id, task.goal, status, step, task.max_steps, data)
        self._save(updated)
        return updated

    def cancel(self, task_id: str) -> TaskRecord:
        task = self.get(task_id)
        if not task:
            raise KeyError(task_id)
        return self.checkpoint(task.id, task.step, task.checkpoint, "canceled")

    def _save(self, task: TaskRecord) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO tasks VALUES(?,?,?,?,?,?,?)",
            (
                task.id,
                task.goal,
                task.status,
                task.step,
                task.max_steps,
                json.dumps(task.checkpoint),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self.db.commit()
