from collections.abc import Iterable
from .tools import Tool
class ToolRegistry:
    def __init__(self,tools:Iterable[Tool]=()):self._tools={};[self.add(t) for t in tools]
    def add(self,tool:Tool):
        if tool.name in self._tools:raise ValueError(f"duplicate tool: {tool.name}")
        self._tools[tool.name]=tool
    def get(self,name):return self._tools.get(name)
    def catalogue(self):return [t.manifest() for t in self._tools.values()]
