from __future__ import annotations

from dataclasses import dataclass
import gc
import json
from pathlib import Path
import re
import subprocess
from typing import Protocol

from skillinquisitor.models import LLMModelConfig, ScanConfig


class LLMDependencyError(RuntimeError):
    """Raised when optional LLM runtime dependencies are unavailable."""


@dataclass(frozen=True)
class HardwareProfile:
    accelerator: str
    gpu_vram_gb: float | None = None


class CodeAnalysisModel(Protocol):
    model_id: str

    def load(self) -> None:
        """Load model state into memory."""

    def generate_structured(self, prompt: str, max_tokens: int) -> dict[str, object]:
        """Return a structured JSON-like response."""

    def unload(self) -> None:
        """Release model state from memory."""


def has_llm_runtime_dependencies() -> bool:
    try:
        import huggingface_hub  # noqa: F401
        import llama_cpp  # noqa: F401
    except ImportError:
        return False
    return True


def detect_hardware_profile(device_policy: str = "auto") -> HardwareProfile:
    lowered = device_policy.lower()
    if lowered == "cpu":
        return HardwareProfile(accelerator="cpu", gpu_vram_gb=None)

    if lowered in {"cuda", "gpu"}:
        return _detect_gpu_profile() or HardwareProfile(accelerator="cpu", gpu_vram_gb=None)

    if lowered == "auto":
        return _detect_gpu_profile() or HardwareProfile(accelerator="cpu", gpu_vram_gb=None)

    return HardwareProfile(accelerator=lowered, gpu_vram_gb=None)


def _detect_gpu_profile() -> HardwareProfile | None:
    try:
        import torch

        if torch.cuda.is_available():
            device_index = torch.cuda.current_device()
            properties = torch.cuda.get_device_properties(device_index)
            total_memory = float(properties.total_memory) / (1024**3)
            return HardwareProfile(accelerator="cuda", gpu_vram_gb=round(total_memory, 2))
        if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
            return HardwareProfile(accelerator="mps", gpu_vram_gb=None)
    except Exception:
        pass

    try:
        completed = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=memory.total",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None

    if completed.returncode != 0:
        return None
    line = next((item.strip() for item in completed.stdout.splitlines() if item.strip()), "")
    if not line:
        return None
    try:
        total_mebibytes = float(line)
    except ValueError:
        return None
    return HardwareProfile(accelerator="cuda", gpu_vram_gb=round(total_mebibytes / 1024.0, 2))


def select_llm_model_group(
    config: ScanConfig,
    *,
    requested_group: str | None = None,
    hardware: HardwareProfile | None = None,
) -> str:
    if requested_group:
        return requested_group

    llm_config = config.layers.llm
    if not llm_config.auto_select_group:
        return llm_config.default_group

    resolved_hardware = hardware or detect_hardware_profile(llm_config.device_policy or config.device)
    if (
        resolved_hardware.accelerator in {"cuda", "gpu"}
        and resolved_hardware.gpu_vram_gb is not None
        and resolved_hardware.gpu_vram_gb >= llm_config.gpu_min_vram_gb_for_balanced
    ):
        return "balanced"
    return llm_config.default_group


def resolve_group_models(
    config: ScanConfig,
    *,
    requested_group: str | None = None,
    hardware: HardwareProfile | None = None,
) -> tuple[str, list[LLMModelConfig]]:
    llm_config = config.layers.llm
    if llm_config.models:
        return requested_group or llm_config.default_group, list(llm_config.models)

    group = select_llm_model_group(config, requested_group=requested_group, hardware=hardware)
    models = list(llm_config.model_groups.get(group, []))
    if models:
        return group, models
    if group != "tiny":
        fallback = list(llm_config.model_groups.get("tiny", []))
        if fallback:
            return "tiny", fallback
    fallback = list(llm_config.model_groups.get(llm_config.default_group, []))
    return llm_config.default_group, fallback


class LlamaCppCodeAnalysisModel:
    def __init__(
        self,
        *,
        model_id: str,
        model_path: Path,
        context_window: int,
        accelerator: str,
    ) -> None:
        self.model_id = model_id
        self.model_path = model_path
        self.context_window = context_window
        self.accelerator = accelerator
        self._llama = None
        self._module = None

    def load(self) -> None:
        try:
            from llama_cpp import Llama
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise LLMDependencyError(
                "LLM dependencies are not installed. Install with `uv sync --extra llm --group dev`."
            ) from exc

        n_gpu_layers = 0
        if self.accelerator in {"cuda", "gpu"}:
            n_gpu_layers = -1

        self._module = Llama
        self._llama = Llama(
            model_path=str(self.model_path),
            n_ctx=self.context_window,
            n_gpu_layers=n_gpu_layers,
            verbose=False,
        )

    def generate_structured(self, prompt: str, max_tokens: int) -> dict[str, object]:
        if self._llama is None:
            raise RuntimeError("Model must be loaded before generation")

        response = self._llama.create_chat_completion(
            messages=[
                {"role": "system", "content": "You are a security code reviewer. Return JSON only."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.0,
            response_format={"type": "json_object"},
        )
        content = response["choices"][0]["message"]["content"]
        if isinstance(content, str):
            return json.loads(content)
        raise ValueError(f"Unexpected llama.cpp response content for model {self.model_id}")

    def unload(self) -> None:
        self._llama = None
        self._module = None
        gc.collect()


class HeuristicCodeAnalysisModel:
    def __init__(self, *, model_id: str) -> None:
        self.model_id = model_id

    def load(self) -> None:
        return None

    def generate_structured(self, prompt: str, max_tokens: int) -> dict[str, object]:
        del max_tokens
        return _heuristic_response(prompt)

    def unload(self) -> None:
        return None


def _heuristic_response(prompt: str) -> dict[str, object]:
    lowered = prompt.lower()
    if "deterministic finding to verify" in lowered and "health" in lowered:
        return {
            "disposition": "dispute",
            "severity": "low",
            "category": "behavioral",
            "message": "The code performs a routine health-check request without sensitive data flow.",
            "confidence": 0.84,
            "behaviors": ["network_send"],
            "evidence": _heuristic_evidence(prompt, ["health", "requests.post", "requests.get", "curl "]),
        }
    if ".env" in lowered and any(token in lowered for token in ("requests.post", "curl ", "fetch(", "invoke-webrequest")):
        return {
            "disposition": "confirm",
            "severity": "critical",
            "category": "data_exfiltration",
            "message": "The script reads sensitive material and transmits it externally.",
            "confidence": 0.93,
            "behaviors": ["credential_theft", "data_exfiltration"],
            "evidence": _heuristic_evidence(prompt, ["open('.env')", "requests.post", "curl ", "fetch("]),
        }
    if "base64" in lowered and any(token in lowered for token in ("exec(", "eval(", "subprocess")):
        return {
            "disposition": "confirm",
            "severity": "high",
            "category": "obfuscation",
            "message": "The file decodes an obfuscated payload and executes it.",
            "confidence": 0.88,
            "behaviors": ["obfuscation", "dynamic_execution"],
            "evidence": _heuristic_evidence(prompt, ["base64", "exec(", "eval(", "subprocess"]),
        }
    if "health" in lowered and any(token in lowered for token in ("requests.get", "curl ", "urllib.request")):
        return {
            "disposition": "dispute" if "deterministic finding to verify" in lowered else "informational",
            "severity": "low",
            "category": "behavioral",
            "message": "The code performs a routine health-check request without sensitive data flow.",
            "confidence": 0.84,
            "behaviors": ["network_send"],
            "evidence": _heuristic_evidence(prompt, ["health", "requests.get", "curl ", "urllib.request"]),
        }
    if "deterministic finding to verify" in lowered:
        return {
            "disposition": "dispute",
            "severity": "low",
            "category": "behavioral",
            "message": "The deterministic signal does not establish malicious behavior in context.",
            "confidence": 0.73,
            "behaviors": [],
            "evidence": [],
        }
    return {
        "disposition": "informational",
        "severity": "low",
        "category": "behavioral",
        "message": "The file contains code that should be reviewed, but no strong malicious behavior is evident.",
        "confidence": 0.61,
        "behaviors": [],
        "evidence": [],
    }


def _heuristic_evidence(prompt: str, needles: list[str]) -> list[str]:
    snippets: list[str] = []
    for needle in needles:
        match = re.search(re.escape(needle), prompt, flags=re.IGNORECASE)
        if match is None:
            continue
        start = max(0, match.start() - 20)
        end = min(len(prompt), match.end() + 20)
        snippets.append(prompt[start:end].strip())
    return snippets or needles[:2]


def build_code_analysis_model(
    *,
    model: LLMModelConfig,
    model_path: Path | None,
    hardware: HardwareProfile,
) -> CodeAnalysisModel:
    runtime = model.runtime.lower()
    if runtime == "heuristic":
        return HeuristicCodeAnalysisModel(model_id=model.id)
    if runtime != "llama_cpp":
        raise ValueError(f"Unsupported LLM model runtime: {runtime}")
    if model_path is None:
        raise ValueError(f"llama.cpp model path is required for {model.id}")
    return LlamaCppCodeAnalysisModel(
        model_id=model.id,
        model_path=model_path,
        context_window=model.context_window,
        accelerator=hardware.accelerator,
    )
