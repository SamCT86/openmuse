import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..models import Action


class ProviderError(RuntimeError): pass
class OpenAICompatiblePlanner:
    def __init__(self,base_url="https://api.openai.com/v1",model="gpt-4.1-mini",api_key=None,max_response_bytes=1_000_000):
        self.base_url=base_url.rstrip("/"); self.model=model; self.api_key=api_key or os.environ.get("OPENAI_API_KEY"); self.max_response_bytes=max_response_bytes
        if not self.api_key: raise ValueError("OpenAI-compatible API key is required")
    def plan(self,goal,tools,history):
        prompt={"goal":goal,"tools":tools,"history":[r.__dict__ for r in history],"instruction":"Return JSON {tool,arguments} or {done:true}. Never output approval_token."}
        body=json.dumps({"model":self.model,"messages":[{"role":"user","content":json.dumps(prompt,default=str)}],"response_format":{"type":"json_object"}}).encode()
        req=Request(self.base_url+"/chat/completions",data=body,headers={"Authorization":f"Bearer {self.api_key}","Content-Type":"application/json"})
        try:
            with urlopen(req,timeout=60) as response: raw=response.read(self.max_response_bytes+1)
        except (HTTPError,URLError,TimeoutError,OSError) as error: raise ProviderError("provider request failed") from error
        if len(raw)>self.max_response_bytes: raise ProviderError("provider response too large")
        try:
            outer=json.loads(raw); content=outer["choices"][0]["message"]["content"]; value=json.loads(content)
        except (KeyError,IndexError,TypeError,ValueError,json.JSONDecodeError) as error: raise ProviderError("invalid provider response") from error
        if not isinstance(value,dict): raise ProviderError("planner response must be an object")
        if value.get("done") is True: return None
        if not isinstance(value.get("tool"),str) or not isinstance(value.get("arguments",{}),dict): raise ProviderError("invalid planner action")
        return Action(value["tool"],value.get("arguments",{}))
