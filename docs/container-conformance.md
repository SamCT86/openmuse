# Reference worker and container conformance

The reference image is intentionally small and credential-free. Build it, push it to a registry, resolve its immutable digest, and run the black-box checks:

```bash
docker build -f docker/reference-worker/Dockerfile -t registry.example/openmuse-worker:review .
docker push registry.example/openmuse-worker:review
python scripts/container_conformance.py registry.example/openmuse-worker@sha256:<digest>
```

The harness starts the image with no network, read-only root, all capabilities dropped, no-new-privileges, non-root UID 65532, PID/memory limits, and a small `noexec` tmpfs. It verifies those observable properties and the JSON stdin/stdout worker protocol. It mounts no host paths and accepts only digest-pinned images.

Passing this harness validates the tested image/runtime pair, not every deployment. Repeat it against the exact production runtime and digest. The host kernel and container runtime remain in the trusted computing base; use VM isolation when that boundary is insufficient.
