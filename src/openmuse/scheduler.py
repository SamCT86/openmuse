"""Cron-like schedules with deterministic next-fire math and durable jobs."""

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
from zoneinfo import ZoneInfo

RANGES = {"minute": (0, 59), "hour": (0, 23), "dom": (1, 31), "month": (1, 12), "dow": (0, 7)}


def _parse_field(spec: str, low: int, high: int) -> set[int]:
    values: set[int] = set()
    for part in spec.split(","):
        step = 1
        if "/" in part:
            part, raw_step = part.split("/", 1)
            step = int(raw_step)
            if step < 1:
                raise ValueError("step must be positive")
        if part in {"*", ""}:
            start, end = low, high
        elif "-" in part:
            start, end = (int(x) for x in part.split("-", 1))
        else:
            start = end = int(part)
        if start < low or end > high or start > end:
            raise ValueError(f"field value out of range: {part}")
        values.update(range(start, end + 1, step))
    if high == 7:  # day-of-week: 0 and 7 are both Sunday
        values = {0 if v == 7 else v for v in values}
    return values


class CronSchedule:
    """Five-field cron expression: minute hour day-of-month month day-of-week."""

    def __init__(self, expression: str, timezone_name: str = "UTC") -> None:
        fields = expression.split()
        if len(fields) != 5:
            raise ValueError("cron expression needs five fields")
        self.expression = expression
        self.timezone_name = timezone_name
        self.timezone = ZoneInfo(timezone_name)
        self.minutes = _parse_field(fields[0], *RANGES["minute"])
        self.hours = _parse_field(fields[1], *RANGES["hour"])
        self.dom = _parse_field(fields[2], *RANGES["dom"])
        self.months = _parse_field(fields[3], *RANGES["month"])
        self.dow = _parse_field(fields[4], *RANGES["dow"])
        self.dom_any = fields[2] == "*"
        self.dow_any = fields[4] == "*"

    def next_after(self, moment: datetime) -> datetime:
        """First fire time strictly after `moment`; matches standard cron OR semantics."""
        candidate = moment.astimezone(self.timezone).replace(second=0, microsecond=0) + timedelta(minutes=1)
        for _ in range(366 * 5):
            if candidate.month in self.months and self._day_matches(candidate):
                for hour in sorted(self.hours):
                    if hour < candidate.hour:
                        continue
                    for minute in sorted(self.minutes):
                        fired = candidate.replace(hour=hour, minute=minute)
                        if fired >= candidate:
                            return fired.astimezone(timezone.utc)
            candidate = (candidate + timedelta(days=1)).replace(hour=0, minute=0)
        raise ValueError("schedule has no fire time within five years")

    def _day_matches(self, moment: datetime) -> bool:
        cron_dow = (moment.weekday() + 1) % 7
        dom_hit, dow_hit = moment.day in self.dom, cron_dow in self.dow
        if self.dom_any and self.dow_any:
            return True
        if self.dom_any:
            return dow_hit
        if self.dow_any:
            return dom_hit
        return dom_hit or dow_hit


@dataclass(frozen=True)
class Job:
    id: str
    schedule: str
    goal: str
    last_run: str | None


class Scheduler:
    """Durable cron jobs; `due` is pure selection, execution stays external."""

    def __init__(self, path: Path) -> None:
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, schedule TEXT, goal TEXT, last_run TEXT)")
        self.db.commit()

    def add(self, schedule: str, goal: str) -> Job:
        CronSchedule(schedule)
        job = Job(uuid4().hex, schedule, goal, None)
        self.db.execute("INSERT INTO jobs VALUES(?,?,?,?)", (job.id, job.schedule, job.goal, job.last_run))
        self.db.commit()
        return job

    def remove(self, job_id: str) -> None:
        self.db.execute("DELETE FROM jobs WHERE id=?", (job_id,))
        self.db.commit()

    def jobs(self) -> list[Job]:
        rows = self.db.execute("SELECT id,schedule,goal,last_run FROM jobs ORDER BY id").fetchall()
        return [Job(*row) for row in rows]

    def due(self, now: datetime) -> list[Job]:
        ready = []
        for job in self.jobs():
            schedule = CronSchedule(job.schedule)
            anchor = datetime.fromisoformat(job.last_run) if job.last_run else now - timedelta(minutes=1)
            if schedule.next_after(anchor) <= now:
                ready.append(job)
        return ready

    def claim_due(self, now: datetime) -> list[Job]:
        """Atomically claim due jobs so concurrent workers cannot double-run them."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            ready = self.due(now)
            for job in ready:
                self.db.execute("UPDATE jobs SET last_run=? WHERE id=?", (now.isoformat(), job.id))
            self.db.commit()
            return ready
        except Exception:
            self.db.rollback()
            raise

    def mark_run(self, job_id: str, ran_at: datetime) -> None:
        self.db.execute("UPDATE jobs SET last_run=? WHERE id=?", (ran_at.isoformat(), job_id))
        self.db.commit()
