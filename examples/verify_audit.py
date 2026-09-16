"""Verify an OpenMuse JSONL audit hash chain without trusting the runtime."""

import argparse
from pathlib import Path

from openmuse.audit import verify_chain


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", default=".openmuse-demo/audit.jsonl")
    args = parser.parse_args()
    valid, records, error = verify_chain(Path(args.path))
    if valid:
        print(f"VERIFIED: {records} records form an intact hash chain")
        return 0
    print(f"INVALID at record {records}: {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
