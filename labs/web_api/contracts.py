from typing import Literal

from pydantic import BaseModel, ConfigDict

from faultloom_protocol.base import Identifier
from faultloom_web.web_api import WebApiRunRequest


class WebApiFixture(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["0.1.0"]
    namespace: Literal["faultloom.lab.web.api.v1"]
    fixture_id: Identifier
    positive: WebApiRunRequest
    negative: WebApiRunRequest
    expected_async_effect_id: Identifier
    expected_chain_edge_id: Identifier
