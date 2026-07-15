from __future__ import annotations


class ProviderOutputError(RuntimeError):
    pass


class ProviderOutputIntegrityError(ProviderOutputError):
    pass


class ProviderOutputScopeError(ProviderOutputError):
    pass
