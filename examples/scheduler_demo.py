"""Persist and atomically claim one due cron job."""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from openmuse.scheduler import Scheduler

with tempfile.TemporaryDirectory(prefix="openmuse-scheduler-") as directory:
    scheduler = Scheduler(Path(directory) / "jobs.db")
    job = scheduler.add("* * * * *", "verify the audit chain")
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    claimed = scheduler.claim_due(now)
    claimed_again = scheduler.claim_due(now)
    print(f"created={job.goal!r} schedule={job.schedule!r}")
    print(f"first_claim={len(claimed)} second_claim={len(claimed_again)}")
