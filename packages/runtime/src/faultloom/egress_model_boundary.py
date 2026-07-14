from __future__ import annotations

from dataclasses import dataclass

from faultloom.egress_enum_integrity import IdentityValue, exact_dict_entries
from faultloom.egress_wire import EgressWireError, ExactEnumCatalog
from faultloom_protocol import ProtocolModel


@dataclass(frozen=True, slots=True)
class ExactModelBoundary:
    enum_catalog: ExactEnumCatalog

    def prepare(self, value: IdentityValue) -> IdentityValue:
        entries = exact_dict_entries(
            value,
            value_type=None,
            error=EgressWireError("key_type"),
        )
        self.enum_catalog.validate_integrity()
        return {key: child for key, child in entries}

    def finish[ModelT: ProtocolModel](self, model: ModelT) -> ModelT:
        self.enum_catalog.validate_integrity()
        return model
