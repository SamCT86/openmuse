# First-run self-rehearsal

Measured 2026-09-30 on GitHub Actions, from commit
`9d86cc47e79a290421488baf1a5e48c3525ddf01`.

- Environment: fresh `python:3.12-slim` Docker container, Linux amd64.
- Clock: 19 seconds from Git provisioning through checkout, virtualenv,
  README editable install, first approved file action, audit verification,
  and installed browser-chat startup/teardown. Image pull is outside this clock.
- Result: pass within the 15-minute limit.
- Audit: 5 records, intact chain; approved action digest matches executed action.
- Chat: installed `openmuse-chat`, explicit offline demo planner, temporary
  workspace, ephemeral localhost port, recognizable landing page, process stopped.
- Evidence: https://github.com/tahodev/openmuse/actions/runs/36698409705/job/109831810467

This is an automated self-rehearsal using a scripted approval, not an external
user study. Network speed and runner hardware influence the timing. It does not
measure time reading the README or understanding the approval card. Native
Windows failed at the POSIX `fcntl` import; the workspace file tools also require
POSIX directory-descriptor APIs. Issue #30 remains open. No compatibility
fallback that weakens file or audit safety has been added.

The CI job repeats this check for later commits and fails at 900 seconds.


## Windows through WSL

Verified 2026-09-30 on `windows-latest` with Ubuntu installed via
`wsl --install --distribution Ubuntu --web-download --no-launch`.
Inside WSL: Python venv, README editable install, scripted approval demo,
5-record intact audit chain and matching action digest, installed offline chat
landing page on an ephemeral localhost port, and process teardown all passed.
CI uses an unattended root user; users should use their normal Ubuntu account.
The script normalizes PowerShell CRLF to LF before handing it to Bash.

Evidence: https://github.com/tahodev/openmuse/actions/runs/36699301600/job/109834689784

Native Windows support is still a separate design-review track, not included.
