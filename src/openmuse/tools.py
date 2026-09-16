"""Tool protocol plus workspace-safe file tools and SSRF-resistant fetch."""
import ipaddress,socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any,Protocol
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler,Request,build_opener
from .policy import Risk
class Tool(Protocol):
    name:str;description:str;risk:Risk
    def run(self,**kwargs:Any)->str:...
    def manifest(self)->dict[str,Any]:...
class ManifestMixin:
    def manifest(self):return {"name":self.name,"description":self.description,"risk":self.risk.value,"schema":self.schema}
def safe_path(root:Path,raw:str,write=False)->Path:
    root=root.resolve();target=(root/raw).resolve(strict=False)
    if target!=root and root not in target.parents:raise ValueError("path escapes workspace")
    cursor=target.parent if write else target
    while cursor!=root:
        if cursor.is_symlink():raise ValueError("symlink paths are blocked")
        cursor=cursor.parent
    return target
@dataclass
class ReadFile(ManifestMixin):
    workspace:Path=Path.cwd();name:str="read_file";description:str="Read UTF-8 text in workspace";risk:Risk=Risk.READ;schema=None
    def __post_init__(self):self.schema={"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}
    def run(self,path:str,**_:Any)->str:return safe_path(self.workspace,path).read_text(encoding="utf-8")
@dataclass
class WriteFile(ManifestMixin):
    workspace:Path=Path.cwd();name:str="write_file";description:str="Write UTF-8 text in workspace";risk:Risk=Risk.WRITE;schema=None
    def __post_init__(self):self.schema={"type":"object","required":["path","content"],"properties":{"path":{"type":"string"},"content":{"type":"string"}}}
    def run(self,path:str,content:str,**_:Any)->str:
        target=safe_path(self.workspace,path,True);target.parent.mkdir(parents=True,exist_ok=True)
        if target.is_symlink():raise ValueError("symlink target blocked")
        target.write_text(content,encoding="utf-8");return f"wrote {target.relative_to(self.workspace.resolve())}"
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
@dataclass
class FetchURL(ManifestMixin):
    name:str="fetch_url";description:str="Fetch a public HTTP(S) URL";risk:Risk=Risk.READ;schema=None
    def __post_init__(self):self.schema={"type":"object","required":["url"],"properties":{"url":{"type":"string"}}}
    def run(self,url:str,**_:Any)->str:
        p=urlsplit(url)
        if p.scheme not in {"http","https"} or not p.hostname or p.username:raise ValueError("invalid public URL")
        if p.port not in {None,80,443}:raise ValueError("nonstandard port blocked")
        for info in socket.getaddrinfo(p.hostname,p.port or (443 if p.scheme=="https" else 80)):
            if not ipaddress.ip_address(info[4][0]).is_global:raise ValueError("private or special-use network blocked")
        with build_opener(NoRedirect).open(Request(url,headers={"User-Agent":"OpenMuse/0.2"}),timeout=15) as r:return r.read(200_001)[:200_000].decode("utf-8",errors="replace")
