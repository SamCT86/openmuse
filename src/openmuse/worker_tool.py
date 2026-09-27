"""Host-described, effect-free container worker adapter.

A worker cannot pick its own risk or host RPC. It gets only validated JSON
arguments and returns a bounded JSON response. A deployer must validate the
container runtime and pinned image; no filesystem, network, or host effect RPC
is exposed here. An untrusted plugin requiring effects is unsupported.
"""

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from .container_worker import ContainerWorker
from .policy import Risk


@dataclass
class WorkerTool:
    worker: ContainerWorker
    name: str
    description: str
    schema: dict[str, Any]
    risk: Risk = field(default=Risk.READ, init=False)

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.schema, dict):
            raise ValueError("worker tool needs a host-provided name and schema")
        self.schema = deepcopy(self.schema)

    def manifest(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "risk": self.risk.value, "schema": deepcopy(self.schema)}

    def run(self, **kwargs: Any) -> str:
        import json

        response = self.worker.run({"arguments": kwargs}).output
        return json.dumps(response, sort_keys=True)
