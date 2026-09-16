"""Small in-process web-channel adapter for demos and tests."""

from collections import deque

from .base import IncomingMessage


class WebChannel:
    def __init__(self) -> None:
        self.inbox: deque[IncomingMessage] = deque()
        self.outbox: list[tuple[str, str]] = []

    def submit(self, conversation_id: str, sender_id: str, text: str) -> None:
        self.inbox.append(IncomingMessage("web", conversation_id, sender_id, text))

    def receive(self) -> IncomingMessage | None:
        return self.inbox.popleft() if self.inbox else None

    def send(self, conversation_id: str, text: str) -> str:
        self.outbox.append((conversation_id, text))
        return f"web:{len(self.outbox)}"
