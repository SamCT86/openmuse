"""Verify an OpenMuse JSONL audit hash chain without trusting the runtime."""

import argparse
import json
from pathlib import Path

from openmuse.audit import verify_chain


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", default=".openmuse-demo/audit.jsonl")
    args = parser.parse_args()
    valid, records, error = verify_chain(Path(args.path))
    if valid:
        with Path(args.path).open(encoding="utf-8") as source:
            audit_records = [json.loads(line) for line in source]
        pending = next(
            (record["action"] for record in audit_records if record.get("error_code") == "approval_required"),
            None,
        )
        executed = next(
            (
                record["action"]
                for record in audit_records
                if pending
                and record.get("status") == "completed"
                and record.get("action", {}).get("id") == pending["id"]
            ),
            None,
        )
        if pending is None or executed is None or pending != executed:
            print("INVALID: approved action does not match executed action")
            return 1
        action_digest = pending["arguments_sha256"]
        print(f"VERIFIED: {records} records form an intact hash chain")
        print(f"VERIFIED: approved action == executed action ({action_digest[:16]}...)")
        return 0
    print(f"INVALID at record {records}: {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
