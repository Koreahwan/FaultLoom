from __future__ import annotations

import faultloom_protocol.models as m

from tests.protocol.factories import sample_models


def reference_grant() -> m.AuthorityGrant:
    source = sample_models()["AuthorityGrant"].model_dump(mode="python")
    source["pack_ids"] = ("pack.reference",)
    source["adapter_ids"] = ("adapter.reference",)
    policy = source["action_policy"]
    policy["allowed_classes"] = (m.ActionClass.OBSERVE, m.ActionClass.SAFE_PROBE)
    policy["allowed_families"] = ("reference.digest",)
    source["action_policy"] = m.ActionPolicy.model_validate(policy)
    return m.AuthorityGrant.model_validate(source)


def reference_intent() -> m.ActionIntent:
    source = sample_models()["ActionIntent"].model_dump(mode="python")
    source["pack_id"] = "pack.reference"
    source["action_kind"] = "reference.digest"
    source["action_class"] = m.ActionClass.OBSERVE
    return m.ActionIntent.model_validate(source)
