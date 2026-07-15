from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from faultloom_protocol import ResearchDelta

from .models import ResearchPass


class _EventModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
    )


class DeltaEvent(_EventModel):
    pass_kind: ResearchPass
    delta: ResearchDelta
