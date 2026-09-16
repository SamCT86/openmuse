"""Portable user-channel interface."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class IncomingMessage:
    channel: str
    conversation_id: str
    sender_id: str
    text: str


class Channel(Protocol):
    def receive(self) -> IncomingMessage | None: ...
    def send(self, conversation_id: str, text: str) -> str: ...
