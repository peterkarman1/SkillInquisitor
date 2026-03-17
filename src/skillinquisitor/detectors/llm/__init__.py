from __future__ import annotations

from importlib import import_module

__all__ = [
    "LLMCodeJudge",
    "LLMTarget",
    "HardwareProfile",
    "download_llm_models",
    "has_llm_runtime_dependencies",
    "list_llm_model_statuses",
    "select_llm_model_group",
]


def __getattr__(name: str):
    if name in {"LLMCodeJudge", "LLMTarget"}:
        module = import_module("skillinquisitor.detectors.llm.judge")
        return getattr(module, name)
    if name in {"HardwareProfile", "has_llm_runtime_dependencies", "select_llm_model_group"}:
        module = import_module("skillinquisitor.detectors.llm.models")
        return getattr(module, name)
    if name in {"download_llm_models", "list_llm_model_statuses"}:
        module = import_module("skillinquisitor.detectors.llm.download")
        return getattr(module, name)
    raise AttributeError(name)
