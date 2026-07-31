"""Provider function-tool contract for one bounded automation model turn.

The OpenAI-compatible transport admits only a deliberately small JSON Schema
subset.  This module is therefore separate from ``ModelTurn.model_json_schema``:
Pydantic's richer schema includes references and validation keywords which must
remain coordinator-side checks.
"""

from __future__ import annotations

from faultloom.egress_wire import WireValue
from faultloom.provider import (
    OpenAICompatibleFunctionSchema,
    ProviderToolKind,
    ProviderToolSpec,
    provider_canonical_json_bytes,
    provider_sha256_digest,
)


# This identifier is intentionally valid both for the provider tool contract
# and the OpenAI-compatible function-name grammar.
MODEL_TURN_TOOL_ID = "faultloom-model-turn-v1"
MODEL_TURN_WIRE_NAME = "faultloom-model-turn-v1"


def _object(
    properties: dict[str, WireValue],
    required: tuple[str, ...],
) -> dict[str, WireValue]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


def _array(items: dict[str, WireValue]) -> dict[str, WireValue]:
    return {"type": "array", "items": items}


def model_turn_function_schema() -> dict[str, WireValue]:
    """Return the restricted function-argument schema for ``ModelTurn``.

    Bounds, identifier formats, enum membership, and cross-field bindings are
    enforced by the coordinator's Pydantic validation after provider parsing.
    Optional Pydantic fields are represented by omitted object properties: the
    provider schema subset deliberately has no union types.
    """

    text: dict[str, WireValue] = {"type": "string"}
    integer: dict[str, WireValue] = {"type": "integer"}
    boolean: dict[str, WireValue] = {"type": "boolean"}

    hypothesis = _object(
        {
            "proposal_id": text,
            "statement": text,
            "provenance": _array(text),
            "supporting_evidence_ids": _array(text),
            "contradicting_evidence_ids": _array(text),
            "prerequisite_ids": _array(text),
        },
        (
            "proposal_id",
            "statement",
            "provenance",
            "supporting_evidence_ids",
            "contradicting_evidence_ids",
            "prerequisite_ids",
        ),
    )
    negative_result = _object(
        {
            "hypothesis_proposal_id": text,
            "experiment_digest": text,
            "conclusion": text,
            "evidence_ids": _array(text),
        },
        (
            "hypothesis_proposal_id",
            "experiment_digest",
            "conclusion",
            "evidence_ids",
        ),
    )
    estimate = _object(
        {
            "rate_slots": integer,
            "duration_seconds": integer,
            "bytes": integer,
            "concurrency": integer,
            "cost_microunits": integer,
        },
        (
            "rate_slots",
            "duration_seconds",
            "bytes",
            "concurrency",
            "cost_microunits",
        ),
    )
    action = _object(
        {
            "candidate_id": text,
            "hypothesis_proposal_id": text,
            "adapter_id": text,
            "capability": text,
            "action_kind": text,
            "action_class": text,
            "expected_information_gain_bps": integer,
            "estimate": estimate,
        },
        (
            "candidate_id",
            "hypothesis_proposal_id",
            "adapter_id",
            "capability",
            "action_kind",
            "action_class",
            "expected_information_gain_bps",
            "estimate",
        ),
    )
    poc_step = _object(
        {
            "step_id": text,
            "action_class": text,
            "action_kind": text,
            "method": text,
            "payload_digest": text,
            "expected_effect": text,
            "negative_control": text,
            "required": boolean,
            "hazard": text,
        },
        (
            "step_id",
            "action_class",
            "action_kind",
            "method",
            "expected_effect",
            "negative_control",
            "hazard",
        ),
    )
    poc = _object(
        {
            "adaptation_id": text,
            "recipe_id": text,
            "hypothesis_proposal_id": text,
            "expected_observable_effect": text,
            "negative_controls": _array(text),
            "evidence_ids": _array(text),
            "steps": _array(poc_step),
        },
        (
            "adaptation_id",
            "recipe_id",
            "hypothesis_proposal_id",
            "expected_observable_effect",
            "negative_controls",
            "evidence_ids",
            "steps",
        ),
    )
    finding_draft = _object(
        {
            "hypothesis_proposal_id": text,
            "poc_recipe_id": text,
            "title": text,
            "severity": text,
            "summary": text,
            "impact": text,
            "reproduction_steps": _array(text),
            "remediation": text,
        },
        (
            "hypothesis_proposal_id",
            "title",
            "severity",
            "summary",
            "impact",
            "reproduction_steps",
            "remediation",
        ),
    )
    return _object(
        {
            "hypotheses": _array(hypothesis),
            "negative_results": _array(negative_result),
            "actions": _array(action),
            "poc": poc,
            "finding_draft": finding_draft,
            "stop_reason": text,
        },
        ("hypotheses", "negative_results", "actions", "stop_reason"),
    )


def model_turn_function_schema_bytes() -> bytes:
    """Return the exact canonical parameter-schema source attested to a provider."""

    return provider_canonical_json_bytes(model_turn_function_schema())


def model_turn_provider_output_schema() -> dict[str, WireValue]:
    """Return the inert acknowledgement schema bound to the provider contract.

    This tool is never executed by the coordinator, so its provider-side output
    schema is only a stable attestation slot; model output is the function call
    arguments and is parsed by ``ModelTurn`` after receipt verification.
    """

    return _object({}, ())


def model_turn_provider_tool_spec() -> ProviderToolSpec:
    """Build the stable provider tool contract for a structured model turn."""

    return ProviderToolSpec(
        tool_id=MODEL_TURN_TOOL_ID,
        wire_name=MODEL_TURN_WIRE_NAME,
        kind=ProviderToolKind.FUNCTION,
        input_schema_digest=provider_sha256_digest(model_turn_function_schema()),
        output_schema_digest=provider_sha256_digest(model_turn_provider_output_schema()),
    )


def model_turn_openai_function_schema() -> OpenAICompatibleFunctionSchema:
    """Build an admitted OpenAI-compatible function schema with no transport."""

    return OpenAICompatibleFunctionSchema(
        tool=model_turn_provider_tool_spec(),
        name=MODEL_TURN_WIRE_NAME,
        schema_bytes=model_turn_function_schema_bytes(),
    )


__all__ = [
    "MODEL_TURN_TOOL_ID",
    "MODEL_TURN_WIRE_NAME",
    "model_turn_function_schema",
    "model_turn_function_schema_bytes",
    "model_turn_openai_function_schema",
    "model_turn_provider_output_schema",
    "model_turn_provider_tool_spec",
]
