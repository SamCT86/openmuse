# Independent security review process

1. Freeze a commit and run the `Security review evidence` workflow.
2. Give an independent reviewer the public reviewer brief, checklist, threat model, source commit, and generated evidence artifact.
3. Require severity, prerequisites, deterministic reproduction, impact, remediation, and retest status for every finding.
4. Track safe-to-disclose findings publicly. Keep credential-bearing reproductions private.
5. Do not mark the independent-review production gate complete until a reviewer unaffiliated with implementation signs off on the exact commit and remediations are retested.

This repository can prepare evidence but cannot self-attest an independent review.
