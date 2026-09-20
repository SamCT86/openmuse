"""Generate deterministic security-review evidence from the checkout."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def run(*command): return subprocess.run(command,cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip()
def main():
    evidence={"commit":run("git","rev-parse","HEAD"),"python":run("python","--version"),"tests_sha256":hashlib.sha256(run("pytest","-q").encode()).hexdigest(),"tree_sha256":hashlib.sha256(run("git","ls-files","-s").encode()).hexdigest()}
    output=ROOT/"security-evidence.json"; output.write_text(json.dumps(evidence,sort_keys=True,indent=2)+"\n"); print(output)
if __name__=="__main__": main()
