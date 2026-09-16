"""Policy envelope for a separately deployed browser worker."""

from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import urlsplit


@dataclass(frozen=True)
class BrowserJob:
    url: str
    action: str
    allowed_domains: frozenset[str]
    read_only: bool = True


class BrowserWorkerPolicy:
    MUTATIONS: ClassVar[set[str]] = {"click", "fill", "submit", "upload", "download"}

    def validate(self, job: BrowserJob) -> None:
        host = urlsplit(job.url).hostname
        if not host or host not in job.allowed_domains:
            raise ValueError("domain outside worker allowlist")
        if job.read_only and job.action in self.MUTATIONS:
            raise ValueError("mutation blocked in read-only worker")
