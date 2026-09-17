"""Cron math and durable job selection."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from openmuse.scheduler import CronSchedule, Scheduler

UTC = timezone.utc


def at(y, mo, d, h, mi):
    return datetime(y, mo, d, h, mi, tzinfo=UTC)


def test_every_fifteen_minutes():
    schedule = CronSchedule("*/15 * * * *")
    assert schedule.next_after(at(2026, 9, 17, 10, 7)) == at(2026, 9, 17, 10, 15)
    assert schedule.next_after(at(2026, 9, 17, 10, 15)) == at(2026, 9, 17, 10, 30)


def test_specific_weekday_and_ranges():
    monday_nine = CronSchedule("0 9 * * 1")
    assert monday_nine.next_after(at(2026, 9, 17, 0, 0)) == at(2026, 9, 21, 9, 0)
    work_hours = CronSchedule("0 9-17 * * 1-5")
    assert work_hours.next_after(at(2026, 9, 18, 17, 0)) == at(2026, 9, 21, 9, 0)


def test_dom_dow_or_semantics():
    schedule = CronSchedule("0 0 13 * 5")  # the 13th OR any Friday
    assert schedule.next_after(at(2026, 9, 12, 0, 0)) == at(2026, 9, 13, 0, 0)
    both_free = CronSchedule("0 0 * * *")
    assert both_free.next_after(at(2026, 9, 17, 0, 0)) == at(2026, 9, 18, 0, 0)


def test_sunday_aliases_and_lists():
    assert CronSchedule("0 8 * * 0").next_after(at(2026, 9, 19, 0, 0)) == at(2026, 9, 20, 8, 0)
    assert CronSchedule("0 8 * * 7").next_after(at(2026, 9, 20, 8, 0)) == at(2026, 9, 27, 8, 0)
    listed = CronSchedule("30 6,18 1,15 * *")
    assert listed.next_after(at(2026, 9, 1, 6, 30)) == at(2026, 9, 1, 18, 30)


def test_invalid_expressions_rejected():
    for bad in ("* * * *", "61 * * * *", "0 9 * * 8", "*/0 * * * *", "5-1 * * * *"):
        with pytest.raises(ValueError):
            CronSchedule(bad)


def test_scheduler_due_jobs_and_persistence(tmp_path: Path):
    scheduler = Scheduler(tmp_path / "jobs.db")
    every_minute = scheduler.add("* * * * *", "sweep inbox")
    daily = scheduler.add("0 9 * * *", "morning brief")
    now = at(2026, 9, 17, 12, 30)

    due = scheduler.due(now)
    assert {job.id for job in due} == {every_minute.id}

    scheduler.mark_run(every_minute.id, now)
    assert scheduler.due(now) == []
    assert [job.id for job in scheduler.due(at(2026, 9, 17, 12, 31))] == [every_minute.id]

    reopened = Scheduler(tmp_path / "jobs.db")
    assert {job.goal for job in reopened.jobs()} == {"sweep inbox", "morning brief"}
    reopened.remove(daily.id)
    assert {job.goal for job in Scheduler(tmp_path / "jobs.db").jobs()} == {"sweep inbox"}


def test_add_rejects_bad_schedule(tmp_path: Path):
    with pytest.raises(ValueError):
        Scheduler(tmp_path / "jobs.db").add("not cron", "x")
