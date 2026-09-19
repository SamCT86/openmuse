"""Child entrypoint for the credential-free isolated-worker demo."""

import json
import os
import sys

request = json.load(sys.stdin)
print(
    json.dumps(
        {
            "child_pid": os.getpid(),
            "cwd_name": os.path.basename(os.getcwd()),
            "message": request["message"],
            "sum": sum(request["numbers"]),
        }
    )
)
