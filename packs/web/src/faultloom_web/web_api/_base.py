from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class WebApiModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


@dataclass(frozen=True, slots=True)
class WebApiIntegrationError(ValueError):
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


class SchemaKind(StrEnum):
    OPENAPI = "openapi"
    GRAPHQL = "graphql"


class WebApiSource(StrEnum):
    IDENTITY_WORKFLOW = "identity_workflow"
    API_ASYNC = "api_async"
