from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from faultloom_protocol import ObservationRef
from faultloom_protocol.base import Identifier, Sha256Digest

from ._base import LlmPackModel
from .errors import LlmPackError


class ContentSource(StrEnum):
    WEB_INPUT = "web_input"
    RAG_DOCUMENT = "rag_document"
    MCP_OUTPUT = "mcp_output"


class UntrustedContent(LlmPackModel):
    content_id: Identifier
    run_id: Identifier
    tenant_id: Identifier
    source: ContentSource
    content_digest: Sha256Digest
    source_observation: ObservationRef
    trusted: Literal[False] = False

    @model_validator(mode="after")
    def _observation_matches_run(self) -> Self:
        if self.source_observation.run_id != self.run_id:
            raise LlmPackError(
                "llm.content_run_mismatch",
                "untrusted content and its observation must share one run",
            )
        return self


class RetrievalDocument(LlmPackModel):
    document_id: Identifier
    collection_id: Identifier
    tenant_id: Identifier
    content: UntrustedContent

    @model_validator(mode="after")
    def _document_is_rag_content(self) -> Self:
        if self.content.source is not ContentSource.RAG_DOCUMENT:
            raise LlmPackError(
                "llm.retrieval_source_invalid",
                "retrieval documents require RAG provenance",
            )
        if self.content.tenant_id != self.tenant_id:
            raise LlmPackError(
                "llm.retrieval_tenant_mismatch",
                "document metadata and content tenant must match",
            )
        return self


class RetrievalQuery(LlmPackModel):
    query_id: Identifier
    run_id: Identifier
    tenant_id: Identifier
    collection_id: Identifier
    query_digest: Sha256Digest


class RetrievalTraceRequest(LlmPackModel):
    query: RetrievalQuery
    selected_document_ids: tuple[Identifier, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _selection_is_unique(self) -> Self:
        if len(set(self.selected_document_ids)) != len(self.selected_document_ids):
            raise LlmPackError(
                "llm.retrieval_duplicate_document",
                "retrieval selections must be unique",
            )
        return self


class RetrievalObservation(LlmPackModel):
    query: RetrievalQuery
    documents: tuple[RetrievalDocument, ...]
    foreign_document_ids: tuple[Identifier, ...]

    @model_validator(mode="after")
    def _foreign_partition_is_exact(self) -> Self:
        if any(item.content.run_id != self.query.run_id for item in self.documents):
            raise LlmPackError(
                "llm.retrieval_run_mismatch",
                "retrieval evidence belongs to another run",
            )
        expected = tuple(
            sorted(
                item.document_id
                for item in self.documents
                if item.tenant_id != self.query.tenant_id
                or item.collection_id != self.query.collection_id
            )
        )
        if self.foreign_document_ids != expected:
            raise LlmPackError(
                "llm.retrieval_partition_invalid",
                "foreign retrieval IDs must exactly describe tenant drift",
            )
        return self


class RetrievalIndex:
    def __init__(self, documents: tuple[RetrievalDocument, ...]) -> None:
        identifiers = tuple(item.document_id for item in documents)
        if len(set(identifiers)) != len(identifiers):
            raise LlmPackError(
                "llm.retrieval_duplicate_document",
                "retrieval index document IDs must be unique",
            )
        self._documents = tuple(sorted(documents, key=lambda item: item.document_id))

    def retrieve(self, query: RetrievalQuery) -> RetrievalObservation:
        selected = tuple(
            item
            for item in self._documents
            if item.content.run_id == query.run_id
            and item.tenant_id == query.tenant_id
            and item.collection_id == query.collection_id
        )
        return RetrievalObservation(
            query=query,
            documents=selected,
            foreign_document_ids=(),
        )

    def observe(self, request: RetrievalTraceRequest) -> RetrievalObservation:
        by_id = {item.document_id: item for item in self._documents}
        try:
            selected = tuple(by_id[item] for item in request.selected_document_ids)
        except KeyError as exc:
            raise LlmPackError(
                "llm.retrieval_document_unknown",
                "observed retrieval references an unknown document",
            ) from exc
        foreign = tuple(
            sorted(
                item.document_id
                for item in selected
                if item.tenant_id != request.query.tenant_id
                or item.collection_id != request.query.collection_id
            )
        )
        return RetrievalObservation(
            query=request.query,
            documents=selected,
            foreign_document_ids=foreign,
        )
