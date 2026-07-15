"""Shared strict models for the identity/workflow pack boundary."""

from pydantic import BaseModel, ConfigDict


class IdentityWorkflowModel(BaseModel):
    """Strict immutable boundary model for the isolated Web pack."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )
