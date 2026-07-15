from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LlmPackError(ValueError):
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"
