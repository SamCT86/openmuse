# Run a network-isolated container worker

`ContainerWorker` is a production-oriented isolation profile above the local `IsolatedWorker`. The image supplies the worker command; OpenMuse sends one JSON request on stdin and expects one JSON object on stdout.

The default Docker profile has no network, a read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, a non-root user, bounded memory and PIDs, and a small ephemeral `/tmp`. It mounts no host paths. Pin and scan production images by digest.

```python
from openmuse.container_worker import ContainerWorker
worker = ContainerWorker("registry.example/openmuse-browser@sha256:<digest>", ["python", "/app/worker.py"])
result = worker.run({"task": "render"})
```

The host kernel and container runtime enforce these flags. VM isolation, a reviewed image, and deployment-specific validation remain operator responsibilities.
