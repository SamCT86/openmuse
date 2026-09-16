import json
import os
from urllib.request import Request, urlopen

from ..models import Action


class OpenAICompatiblePlanner:
    def __init__(self, base_url="https://api.openai.com/v1", model="gpt-4.1-mini", api_key=None):
        self.base_url = base_url
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")

    def plan(self, goal, tools, history):
        prompt = {
            "goal": goal,
            "tools": tools,
            "history": [r.__dict__ for r in history],
            "instruction": "Return JSON {tool,arguments} or {done:true}. Never output approval_token.",
        }
        body = json.dumps(
            {
                "model": self.model,
                "messages": [{"role": "user", "content": json.dumps(prompt, default=str)}],
                "response_format": {"type": "json_object"},
            }
        ).encode()
        req = Request(
            self.base_url + "/chat/completions",
            data=body,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        )
        with urlopen(req, timeout=60) as response:
            value = json.loads(json.load(response)["choices"][0]["message"]["content"])
        return None if value.get("done") else Action(value["tool"], value.get("arguments", {}))
