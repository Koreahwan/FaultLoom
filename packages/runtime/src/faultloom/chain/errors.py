from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ChainError(ValueError):
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


class ChainIntegrityError(ChainError):
    pass


class ChainPolicyError(ChainError):
    pass
