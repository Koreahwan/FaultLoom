"""Web/API pack exports loaded only when their implementation is requested."""

from importlib import import_module

__all__ = [
    "ActionBoundaryRecord",
    "CapabilitySpec",
    "ChainRunInput",
    "IdentityRunInput",
    "NormalizedWebObservation",
    "ResetStability",
    "SchemaKind",
    "SurfaceRunInput",
    "SurfaceSchemaInput",
    "WebApiCorrelationView",
    "WebApiEvaluation",
    "WebApiHypothesis",
    "WebApiIntegrationError",
    "WebApiRunFacade",
    "WebApiRunRequest",
    "WebApiRunResult",
    "WebApiSource",
    "WebApiVerification",
    "compare_reset_stability",
    "compile_web_action",
    "evaluate_web_api_run",
    "normalize_web_observation",
    "provide_bridge_hypotheses",
    "verify_web_api_run",
    "web_api_manifest",
]

_EXPORT_MODULES = {
    "ActionBoundaryRecord": ".inputs",
    "CapabilitySpec": ".inputs",
    "ChainRunInput": ".inputs",
    "IdentityRunInput": ".inputs",
    "NormalizedWebObservation": ".results",
    "ResetStability": ".results",
    "SchemaKind": "._base",
    "SurfaceRunInput": ".inputs",
    "SurfaceSchemaInput": ".inputs",
    "WebApiCorrelationView": ".results",
    "WebApiEvaluation": ".results",
    "WebApiHypothesis": ".results",
    "WebApiIntegrationError": "._base",
    "WebApiRunFacade": ".runner",
    "WebApiRunRequest": ".inputs",
    "WebApiRunResult": ".results",
    "WebApiSource": "._base",
    "WebApiVerification": ".results",
    "compare_reset_stability": ".descriptors",
    "compile_web_action": ".descriptors",
    "evaluate_web_api_run": ".descriptors",
    "normalize_web_observation": ".descriptors",
    "provide_bridge_hypotheses": ".descriptors",
    "verify_web_api_run": ".descriptors",
    "web_api_manifest": ".manifest",
}


def __getattr__(name: str) -> object:
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value
