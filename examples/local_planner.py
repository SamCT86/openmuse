"""Deterministic end-to-end example: read a note, then stop."""
from pathlib import Path
from openmuse.core import Agent
from openmuse.models import Action
from openmuse.policy import Policy
from openmuse.tools import ReadFile
class Planner:
    def plan(self,goal,tools,history):return None if history else Action("read_file",{"path":"README.md"})
print(Agent([ReadFile()],Policy(),Path('.openmuse/audit.jsonl')).run('Read the README',Planner()))
