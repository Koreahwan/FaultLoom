"""Windows-safe OpenAI-compatible prompt contracts."""

from __future__ import annotations

from typing import Any, Literal, cast

from pydantic import model_validator
from faultloom_protocol.base import NonEmptyStr

from .common import _RuntimeModel, provider_canonical_json_bytes, provider_sha256_digest
from .intent import GenerationConfig


class OpenAICompatibleMessage(_RuntimeModel):
    role: Literal["system", "user", "assistant"]
    content: NonEmptyStr

    def as_wire(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


class OpenAICompatibleChatPayload(_RuntimeModel):
    messages: tuple[OpenAICompatibleMessage, ...]
    generation: GenerationConfig

    @model_validator(mode="after")
    def _requires_message(self) -> "OpenAICompatibleChatPayload":
        if not self.messages:
            raise ValueError("OpenAI-compatible chat payload requires one or more messages")
        return self

    def prompt_material(self) -> dict[str, tuple[dict[str, str], ...]]:
        return {"messages": tuple(message.as_wire() for message in self.messages)}

    def prompt_digest(self) -> str:
        return provider_sha256_digest(cast(Any, self.prompt_material()))

    def prompt_bytes(self) -> int:
        return len(provider_canonical_json_bytes(cast(Any, self.prompt_material())))
