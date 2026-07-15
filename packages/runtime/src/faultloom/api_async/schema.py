from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal, assert_never

from pydantic import BaseModel, ConfigDict, Field

from faultloom_protocol import (
    OperationKind,
    OperationRef,
    SCHEMA_VERSION,
    SchemaEvidence,
)
from faultloom_protocol.base import AwareDatetime, Identifier

from .contracts import (
    SchemaBatch,
    SchemaIngestError,
    UndocumentedObservation,
)


type SchemaSourceKind = Literal["openapi", "graphql"]


class _SchemaBoundaryModel(BaseModel):
    model_config = ConfigDict(
        extra="ignore",
        frozen=True,
        populate_by_name=True,
        strict=True,
    )


class _OpenApiOperation(_SchemaBoundaryModel):
    operation_id: str | None = Field(default=None, alias="operationId")


class _OpenApiPathItem(_SchemaBoundaryModel):
    get: _OpenApiOperation | None = None
    post: _OpenApiOperation | None = None
    put: _OpenApiOperation | None = None
    patch: _OpenApiOperation | None = None
    delete: _OpenApiOperation | None = None


class _OpenApiDocument(_SchemaBoundaryModel):
    openapi: str = Field(min_length=1, max_length=64)
    paths: dict[str, _OpenApiPathItem] = Field(min_length=1)


class SchemaSource(_SchemaBoundaryModel):
    target_id: Identifier
    schema_namespace: Identifier
    observed_at: AwareDatetime


class _GraphRoot(StrEnum):
    QUERY = "Query"
    MUTATION = "Mutation"
    SUBSCRIPTION = "Subscription"


@dataclass(frozen=True, slots=True)
class _OperationSeed:
    source: SchemaSource
    kind: OperationKind
    method: str
    path: str


@dataclass(frozen=True, slots=True)
class _SchemaMaterial:
    source_kind: SchemaSourceKind
    raw: bytes
    operations: tuple[OperationRef, ...]


_GRAPH_ROOT_PATTERN: Final = re.compile(
    r"(?:extend\s+)?type\s+(Query|Mutation|Subscription)\s*\{([^}]*)\}",
    re.MULTILINE | re.DOTALL,
)
_GRAPH_FIELD_PATTERN: Final = re.compile(
    r"^\s*([_A-Za-z][_0-9A-Za-z]*)\s*(?:\([^)]*\))?\s*:",
    re.MULTILINE,
)


def ingest_openapi(raw: bytes, source: SchemaSource) -> SchemaBatch:
    try:
        document = _OpenApiDocument.model_validate_json(raw)
    except ValueError as exc:
        raise SchemaIngestError("OpenAPI document is not a supported schema boundary") from exc
    operations: list[OperationRef] = []
    for path in sorted(document.paths):
        item = document.paths[path]
        method_entries = (
            ("GET", item.get),
            ("POST", item.post),
            ("PUT", item.put),
            ("PATCH", item.patch),
            ("DELETE", item.delete),
        )
        for method, operation in method_entries:
            if operation is None:
                continue
            operations.append(
                _operation(_OperationSeed(source, OperationKind.REST, method, path))
            )
    if not operations:
        raise SchemaIngestError("OpenAPI schema contains no supported operations")
    return _schema_batch(
        source,
        _SchemaMaterial("openapi", raw, tuple(operations)),
    )


def ingest_graphql_sdl(raw: bytes, source: SchemaSource) -> SchemaBatch:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SchemaIngestError("GraphQL SDL must be UTF-8") from exc
    operations: list[OperationRef] = []
    for block in _GRAPH_ROOT_PATTERN.finditer(text):
        try:
            root = _GraphRoot(block.group(1))
        except ValueError as exc:
            raise SchemaIngestError("GraphQL root type is unsupported") from exc
        kind, method, prefix = _graph_root_contract(root)
        for field in sorted(set(_GRAPH_FIELD_PATTERN.findall(block.group(2)))):
            operations.append(
                _operation(
                    _OperationSeed(
                        source,
                        kind,
                        method,
                        f"/graphql#{prefix}.{field}",
                    )
                )
            )
    if not operations:
        raise SchemaIngestError("GraphQL SDL contains no supported root operations")
    return _schema_batch(
        source,
        _SchemaMaterial("graphql", raw, tuple(operations)),
    )


def undocumented_batch(observation: UndocumentedObservation) -> SchemaBatch:
    operation = observation.operation
    drift_id = _stable_id(
        "hypothesis.schema-drift",
        f"{operation.operation_id}\0{observation.source_digest}".encode(),
    )
    evidence = SchemaEvidence(
        schema_version=SCHEMA_VERSION,
        schema_evidence_id=_stable_id(
            "schema-evidence.observed",
            f"{operation.operation_id}\0{observation.source_digest}".encode(),
        ),
        source_kind=observation.source_kind,
        source_digest=observation.source_digest,
        operation_ids=(operation.operation_id,),
        observed_at=observation.observed_at,
        drift_hypothesis_id=drift_id,
    )
    return SchemaBatch(
        batch_id=_stable_id("schema-batch.observed", evidence.schema_evidence_id.encode()),
        operations=(operation,),
        evidence=evidence,
    )


def _graph_root_contract(
    root: _GraphRoot,
) -> tuple[OperationKind, str, str]:
    match root:
        case _GraphRoot.QUERY:
            return OperationKind.GRAPHQL_QUERY, "POST", "query"
        case _GraphRoot.MUTATION:
            return OperationKind.GRAPHQL_MUTATION, "POST", "mutation"
        case _GraphRoot.SUBSCRIPTION:
            return OperationKind.GRAPHQL_SUBSCRIPTION, "WEBSOCKET", "subscription"
        case unreachable:
            assert_never(unreachable)


def _schema_batch(
    source: SchemaSource,
    material: _SchemaMaterial,
) -> SchemaBatch:
    digest = _digest(material.raw)
    evidence = SchemaEvidence(
        schema_version=SCHEMA_VERSION,
        schema_evidence_id=_stable_id("schema-evidence", digest.encode()),
        source_kind=material.source_kind,
        source_digest=digest,
        operation_ids=tuple(item.operation_id for item in material.operations),
        observed_at=source.observed_at,
    )
    return SchemaBatch(
        batch_id=_stable_id("schema-batch", evidence.schema_evidence_id.encode()),
        operations=material.operations,
        evidence=evidence,
    )


def _operation(seed: _OperationSeed) -> OperationRef:
    identity = (
        f"{seed.source.target_id}\0{seed.kind.value}\0{seed.method}\0{seed.path}"
    ).encode()
    return OperationRef(
        schema_version=SCHEMA_VERSION,
        operation_id=_stable_id("operation", identity),
        target_id=seed.source.target_id,
        operation_kind=seed.kind,
        method=seed.method,
        path=seed.path,
        schema_namespace=seed.source.schema_namespace,
        documented=True,
    )


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _stable_id(prefix: str, value: bytes) -> str:
    return f"{prefix}.{hashlib.sha256(value).hexdigest()}"
