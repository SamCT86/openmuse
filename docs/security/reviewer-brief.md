# Independent security reviewer brief

## Scope
Review the OpenMuse runtime at an immutable commit. Focus on the planner-to-tool boundary, approval token binding/consumption, connector grants and revocation, secret injection, FetchURL SSRF controls, process-worker limits, audit verification, and memory provenance.

## Expected attacker capabilities
Assume malicious model output and external content; a compromised connector response; concurrent calls; malformed JSON and tokens; DNS rebinding/redirects; workspace path tricks; and an unprivileged local process. Do not assume the built-in worker has a network namespace or restricted mounts unless the reviewed deployment supplies them.

## Deliverables
For each finding include severity, affected commit/file/line, prerequisites, deterministic reproduction, impact, suggested fix, and whether the issue contradicts the threat model. Include positive assurance for tested boundaries and list areas not assessed.

## Reproduction baseline
Run `ruff check src tests`, `mypy src/openmuse`, `pytest --cov=openmuse --cov-fail-under=85`, build and install the wheel, then inspect the GitHub CodeQL and Python security workflow results for the same commit.
