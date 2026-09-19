# Run a local isolated worker

This walkthrough runs a credential-free JSON job in a separate Python process. It demonstrates the process boundary that exists today. It does **not** add a network namespace, restricted mounts, seccomp, a container, or a VM, so it is not production browser isolation.

## Trust boundary

The trusted host owns `IsolatedWorker`, chooses the child entrypoint and request, creates a dedicated working directory, supplies an explicit environment allowlist, and enforces wall-clock, address-space, open-file, core-dump, and output limits. The child process receives JSON on stdin and must return one JSON object on stdout.

The child is a separate PID, but it still runs under the same OS user and can use the host network and any filesystem paths that OS user can read. Add a container or VM with network and mount policy before using this boundary for untrusted browser jobs or sensitive accounts.

## Run the safe example

From a clean checkout with Python 3.11+:

```bash
git clone https://github.com/tahodev/openmuse.git
cd openmuse
python -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\activate
pip install -e .
python examples/isolated_worker_demo.py
```

Expected output (key order is stable; the PID is intentionally not printed):

```json
{"child_pid": 12345, "cwd_name": ".openmuse-worker-demo", "message": "hello from the host", "sum": 10}
```

`child_pid` will differ on every run. The example only reads its hard-coded JSON input and writes under `.openmuse-worker-demo`; it uses no credentials and performs no external writes.

## See failures fail closed

The automated tests cover the boundaries that are awkward to demonstrate interactively:

```bash
pytest -q tests/test_isolated_worker.py
```

They prove that a parent secret environment variable does not cross the boundary, a timed-out child is killed and raises `TimeoutError`, oversized output is rejected, and any response other than a JSON object is rejected. A non-zero child exit also raises `RuntimeError` with bounded stderr.

For the implementation and deployment limits, read [`isolated_worker.py`](../src/openmuse/isolated_worker.py) and the [threat model](threat-model.md).
