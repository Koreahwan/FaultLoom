from typing import Literal

from pydantic import BaseModel, ConfigDict


class LlmPackModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )

    schema_version: Literal["0.1.0"] = "0.1.0"
