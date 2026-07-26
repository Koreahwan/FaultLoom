"""FaultLoom Web pack."""

from importlib import import_module

__all__ = ["WebApiRunFacade", "identity_workflow_manifest", "web_api_manifest"]

_EXPORT_MODULES = {
    "WebApiRunFacade": ".web_api",
    "identity_workflow_manifest": ".identity_workflow",
    "web_api_manifest": ".web_api",
}


def __getattr__(name: str) -> object:
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value
