from __future__ import annotations

import hashlib
from pathlib import Path

from faultloom.provider import (
    MemoryProviderReceiptJournal,
    ProviderCallIntent,
    ProviderCallReceipt,
    ProviderModelProfile,
    ProviderProxyRequest,
    provider_sha256_digest as sha256_digest,
)
from faultloom.state import StateStore
from faultloom_protocol import Ed25519PublicKeyRecord

from tests.runtime.provider_test_fixtures import (
    FakeProxy,
    PROXY_SIGNER,
    adapter,
    call_intent,
    completed_result,
    profile,
    provider_state_store,
    rehashed_without_resigning,
    signed_proxy_result,
)


TRUSTED_PROXY_KEY: Ed25519PublicKeyRecord = PROXY_SIGNER.public_key_record


def body_digest(body: bytes) -> str:
    return f"sha256:{hashlib.sha256(body).hexdigest()}"


def completed_receipt(
    body: bytes,
    *,
    run_id: str = "run-provider-output",
) -> ProviderCallReceipt:
    model = profile()
    intent = call_intent().model_copy(update={"run_id": run_id})

    def handler(request: ProviderProxyRequest):
        base = completed_result(
            request,
            model,
            intent,
            bytes_received=len(body),
        )
        payload = base.model_dump(
            mode="python",
            exclude={
                "attestation_key_id",
                "attestation_signature",
                "proxy_receipt_digest",
            },
        )
        payload["response_digest"] = body_digest(body)
        return signed_proxy_result(**payload)

    receipt = adapter(
        (model,),
        FakeProxy(handler),
        MemoryProviderReceiptJournal(),
    ).call(intent)
    assert receipt.response_digest == body_digest(body)
    assert receipt.bytes_received == len(body)
    return receipt


def forged_receipt_without_resigning(
    receipt: ProviderCallReceipt,
    **result_updates: object,
) -> ProviderCallReceipt:
    result = receipt.proxy_result
    assert result is not None
    forged_result = rehashed_without_resigning(result, **result_updates)
    document = receipt.model_dump(mode="python")
    document["proxy_result"] = forged_result
    document["proxy_receipt_digest"] = forged_result.proxy_receipt_digest
    draft = ProviderCallReceipt.model_construct(**document)
    document["receipt_digest"] = sha256_digest(
        draft.model_dump(
            mode="python",
            exclude={"receipt_digest"},
            warnings=False,
        )
    )
    return ProviderCallReceipt.model_validate(document)


def output_state_store(
    root: Path,
    *,
    engagement_id: str = "eng.provider-output",
    minimum_anchor=None,
) -> StateStore:
    return provider_state_store(
        root,
        engagement_id=engagement_id,
        minimum_anchor=minimum_anchor,
    )


__all__ = [
    "Ed25519PublicKeyRecord",
    "ProviderCallIntent",
    "ProviderModelProfile",
    "TRUSTED_PROXY_KEY",
    "body_digest",
    "completed_receipt",
    "forged_receipt_without_resigning",
    "output_state_store",
]
