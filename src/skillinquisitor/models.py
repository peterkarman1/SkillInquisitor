from __future__ import annotations

from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field

from skillinquisitor.policies import (
    DEFAULT_AGENT_DIRECTORIES,
    DEFAULT_ALLOWED_FRONTMATTER_FIELDS,
    DEFAULT_FRONTMATTER_FIELD_TYPES,
    DEFAULT_PROTECTED_PACKAGES,
    DEFAULT_PROTECTED_SKILL_NAMES,
    DEFAULT_SHORTENER_HOSTS,
    DEFAULT_TRUSTED_HOSTS,
)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    STEGANOGRAPHY = "steganography"
    OBFUSCATION = "obfuscation"
    CREDENTIAL_THEFT = "credential_theft"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    SUPPLY_CHAIN = "supply_chain"
    JAILBREAK = "jailbreak"
    STRUCTURAL = "structural"
    BEHAVIORAL = "behavioral"
    SUPPRESSION = "suppression"
    CROSS_AGENT = "cross_agent"
    CUSTOM = "custom"


class DetectionLayer(str, Enum):
    DETERMINISTIC = "deterministic"
    ML_ENSEMBLE = "ml_ensemble"
    LLM_ANALYSIS = "llm_analysis"


class FileType(str, Enum):
    MARKDOWN = "markdown"
    PYTHON = "python"
    SHELL = "shell"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    RUBY = "ruby"
    GO = "go"
    RUST = "rust"
    YAML = "yaml"
    UNKNOWN = "unknown"


class SegmentType(str, Enum):
    ORIGINAL = "original"
    HTML_COMMENT = "html_comment"
    CODE_FENCE = "code_fence"
    BASE64_DECODE = "base64_decode"
    HEX_DECODE = "hex_decode"
    ROT13_TRANSFORM = "rot13_transform"
    FRONTMATTER_DESCRIPTION = "frontmatter_description"


class NormalizationType(str, Enum):
    UNICODE_TAG = "unicode_tag"
    ZERO_WIDTH_REMOVAL = "zero_width_removal"
    VARIATION_SELECTOR = "variation_selector"
    BIDI_OVERRIDE = "bidi_override"
    HOMOGLYPH_FOLD = "homoglyph_fold"
    KEYWORD_SPLITTER_COLLAPSE = "keyword_splitter_collapse"


class Location(BaseModel):
    file_path: str = ""
    start_line: int | None = None
    end_line: int | None = None
    start_col: int | None = None
    end_col: int | None = None


class ProvenanceStep(BaseModel):
    segment_type: SegmentType
    source_location: Location | None = None
    description: str = ""


class Segment(BaseModel):
    id: str = ""
    content: str
    normalized_content: str | None = None
    segment_type: SegmentType = SegmentType.ORIGINAL
    location: Location = Field(default_factory=Location)
    provenance_chain: list[ProvenanceStep] = Field(default_factory=list)
    depth: int = 0
    parent_segment_id: str | None = None
    parent_start_offset: int | None = None
    parent_end_offset: int | None = None
    parent_segment_type: SegmentType | None = None
    details: dict[str, object] = Field(default_factory=dict)


class NormalizationTransformation(BaseModel):
    transformation_type: NormalizationType
    original_snippet: str
    normalized_snippet: str
    location: Location | None = None
    details: dict[str, object] = Field(default_factory=dict)


class Artifact(BaseModel):
    path: str
    raw_content: str = ""
    normalized_content: str | None = None
    frontmatter: dict[str, object] = Field(default_factory=dict)
    frontmatter_raw: str | None = None
    frontmatter_location: Location | None = None
    frontmatter_error: str | None = None
    frontmatter_fields: dict[str, Location] = Field(default_factory=dict)
    frontmatter_observations: list[dict[str, object]] = Field(default_factory=list)
    file_type: FileType = FileType.UNKNOWN
    byte_size: int = 0
    is_text: bool = True
    encoding: str | None = None
    is_executable: bool = False
    binary_signature: str | None = None
    normalization_transformations: list[NormalizationTransformation] = Field(default_factory=list)
    segments: list[Segment] = Field(default_factory=list)


class Skill(BaseModel):
    path: str = ""
    name: str | None = None
    artifacts: list[Artifact] = Field(default_factory=list)
    action_flags: list[str] = Field(default_factory=list)
    scan_provenance: str = "declared_skill"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    severity: Severity = Severity.INFO
    category: Category = Category.STRUCTURAL
    layer: DetectionLayer = DetectionLayer.DETERMINISTIC
    rule_id: str = ""
    message: str = ""
    location: Location = Field(default_factory=Location)
    segment_id: str | None = None
    confidence: float | None = None
    action_flags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    details: dict[str, object] = Field(default_factory=dict)


class CheckConfig(BaseModel):
    enabled: bool = True
    checks: dict[str, bool] = Field(default_factory=dict)
    categories: dict[str, bool] = Field(default_factory=dict)
    max_derived_depth: int = 3
    max_derived_segments_per_artifact: int = 64
    max_decode_candidates_per_segment: int = 8
    max_decoded_bytes: int = 4096
    base64_min_length: int = 40
    hex_min_length: int = 32
    require_rot13_signal: bool = True
    soft_rules: list[str] = Field(default_factory=lambda: ["D-10A", "D-14C", "D-15E", "D-15G", "D-18C"])
    soft_fallback_confidence: float = 0.0
    soft_overrides: dict[str, dict[str, float]] = Field(default_factory=dict)


class WeightedModelConfig(BaseModel):
    id: str
    weight: float = 1.0
    type: str | None = None


class LLMModelConfig(BaseModel):
    id: str
    repo_id: str | None = None
    filename: str | None = None
    runtime: str = "llama_cpp"
    weight: float = 1.0
    roles: list[str] = Field(default_factory=lambda: ["general", "targeted", "repo"])
    context_window: int = 8192
    max_output_tokens: int = 512


def _default_ml_models() -> list[WeightedModelConfig]:
    return [
        WeightedModelConfig(
            id="protectai/deberta-v3-base-prompt-injection-v2",
            weight=0.40,
            type="hf_sequence_classifier",
        ),
        WeightedModelConfig(
            id="patronus-studio/wolf-defender-prompt-injection",
            weight=0.35,
            type="hf_sequence_classifier",
        ),
        WeightedModelConfig(
            id="madhurjindal/Jailbreak-Detector",
            weight=0.25,
            type="hf_sequence_classifier",
        ),
    ]


class MLConfig(BaseModel):
    enabled: bool = True
    models: list[WeightedModelConfig] = Field(default_factory=_default_ml_models)
    threshold: float = 0.5
    auto_download: bool = True
    max_concurrency: int = 1
    max_batch_size: int = 8
    min_segment_chars: int = 12
    chunk_max_chars: int = 1800
    chunk_overlap_lines: int = 3


class LLMAPIConfig(BaseModel):
    provider: str | None = None
    model: str | None = None
    api_key_env: str | None = None


class LLMRepomixConfig(BaseModel):
    enabled: bool = True
    command: str = "repomix"
    args: list[str] = Field(default_factory=list)
    max_tokens: int = 30000
    chars_per_token: float = 4.0


def _default_llm_model_groups() -> dict[str, list[LLMModelConfig]]:
    return {
        "tiny": [
            LLMModelConfig(
                id="unsloth/Qwen3.5-0.8B-GGUF",
                repo_id="unsloth/Qwen3.5-0.8B-GGUF",
                filename="Qwen3.5-0.8B-Q8_0.gguf",
                runtime="llama_cpp",
                weight=0.25,
                roles=["general", "targeted", "repo"],
                context_window=8192,
                max_output_tokens=512,
            ),
            LLMModelConfig(
                id="unsloth/Llama-3.2-1B-Instruct-GGUF",
                repo_id="unsloth/Llama-3.2-1B-Instruct-GGUF",
                filename="Llama-3.2-1B-Instruct-Q8_0.gguf",
                runtime="llama_cpp",
                weight=0.25,
                roles=["general", "targeted", "repo"],
                context_window=8192,
                max_output_tokens=512,
            ),
            LLMModelConfig(
                id="bartowski/gemma-2-2b-it-GGUF",
                repo_id="bartowski/gemma-2-2b-it-GGUF",
                filename="gemma-2-2b-it-Q4_K_M.gguf",
                runtime="llama_cpp",
                weight=0.25,
                roles=["general", "targeted", "repo"],
                context_window=8192,
                max_output_tokens=512,
            ),
            LLMModelConfig(
                id="unsloth/Qwen3.5-2B-GGUF",
                repo_id="unsloth/Qwen3.5-2B-GGUF",
                filename="Qwen3.5-2B-Q4_K_M.gguf",
                runtime="llama_cpp",
                weight=0.25,
                roles=["general", "targeted", "repo"],
                context_window=8192,
                max_output_tokens=512,
            ),
        ],
        "balanced": [],
        "large": [],
    }


class LLMConfig(BaseModel):
    enabled: bool = True
    runtime: str = "llama_cpp"
    models: list[LLMModelConfig] = Field(default_factory=list)
    model_groups: dict[str, list[LLMModelConfig]] = Field(default_factory=_default_llm_model_groups)
    default_group: str = "tiny"
    auto_select_group: bool = True
    gpu_min_vram_gb_for_balanced: float = 8.0
    auto_download: bool = True
    device_policy: str = "auto"
    general_threshold: float = 0.55
    targeted_threshold: float = 0.7
    repo_threshold: float = 0.65
    max_output_tokens: int = 512
    deep_analysis: bool = False
    repomix: LLMRepomixConfig = Field(default_factory=LLMRepomixConfig)
    api: LLMAPIConfig = Field(default_factory=LLMAPIConfig)


class LayersConfig(BaseModel):
    deterministic: CheckConfig = Field(default_factory=CheckConfig)
    ml: MLConfig = Field(default_factory=MLConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)


class ScoringWeightsConfig(BaseModel):
    critical: int = 30
    high: int = 20
    medium: int = 10
    low: int = 5


class ScoringConfig(BaseModel):
    weights: ScoringWeightsConfig = Field(default_factory=ScoringWeightsConfig)
    suppression_multiplier: float = 1.5
    chain_absorption: bool = True
    decay_factor: float = 0.7
    severity_floors: dict[str, int] = Field(
        default_factory=lambda: {"critical": 39, "high": 59}
    )
    llm_dispute_factor: float = 0.5
    llm_confirm_factor: float = 0.15
    soft_confirmed_boost: float = 1.5
    soft_confirmation_threshold: float = 0.75


class ChainConfig(BaseModel):
    name: str
    required: list[str]
    severity: Severity


def _default_chains() -> list[ChainConfig]:
    return [
        ChainConfig(
            name="Data Exfiltration",
            required=["READ_SENSITIVE", "NETWORK_SEND"],
            severity=Severity.CRITICAL,
        ),
        ChainConfig(
            name="Credential Theft",
            required=["READ_SENSITIVE", "EXEC_DYNAMIC"],
            severity=Severity.CRITICAL,
        ),
        ChainConfig(
            name="Cloud Metadata SSRF",
            required=["SSRF_METADATA", "NETWORK_SEND"],
            severity=Severity.CRITICAL,
        ),
    ]


class CustomRuleConfig(BaseModel):
    id: str
    pattern: str
    severity: Severity
    category: str
    message: str


class AlertsConfig(BaseModel):
    discord_webhook: str | None = None
    telegram: str | None = None
    slack_webhook: str | None = None


class FrontmatterPolicyConfig(BaseModel):
    allowed_fields: list[str] = Field(default_factory=lambda: list(DEFAULT_ALLOWED_FRONTMATTER_FIELDS))
    field_types: dict[str, str] = Field(default_factory=lambda: dict(DEFAULT_FRONTMATTER_FIELD_TYPES))
    description_max_length: int = 500


class URLPolicyRegistryConfig(BaseModel):
    python: list[str] = Field(default_factory=lambda: ["pypi.org", "files.pythonhosted.org"])
    javascript: list[str] = Field(default_factory=lambda: ["registry.npmjs.org"])
    rust: list[str] = Field(default_factory=lambda: ["crates.io"])


class URLPolicyConfig(BaseModel):
    allow_hosts: list[str] = Field(default_factory=lambda: list(DEFAULT_TRUSTED_HOSTS))
    allow_domain_suffixes: list[str] = Field(default_factory=list)
    allow_schemes: list[str] = Field(default_factory=lambda: ["https"])
    shortener_hosts: list[str] = Field(default_factory=lambda: list(DEFAULT_SHORTENER_HOSTS))
    registry_hosts: URLPolicyRegistryConfig = Field(default_factory=URLPolicyRegistryConfig)
    custom_index_allow_hosts: list[str] = Field(default_factory=list)
    report_allowlisted_urls: bool = False


class ProtectedPackagesConfig(BaseModel):
    python: list[str] = Field(default_factory=lambda: list(DEFAULT_PROTECTED_PACKAGES["python"]))
    javascript: list[str] = Field(default_factory=lambda: list(DEFAULT_PROTECTED_PACKAGES["javascript"]))
    rust: list[str] = Field(default_factory=lambda: list(DEFAULT_PROTECTED_PACKAGES["rust"]))


class TyposquattingAllowPackagesConfig(BaseModel):
    python: list[str] = Field(default_factory=list)
    javascript: list[str] = Field(default_factory=list)
    rust: list[str] = Field(default_factory=list)


class TyposquattingConfig(BaseModel):
    protected_packages: ProtectedPackagesConfig = Field(default_factory=ProtectedPackagesConfig)
    protected_skill_names: list[str] = Field(default_factory=lambda: list(DEFAULT_PROTECTED_SKILL_NAMES))
    allow_packages: TyposquattingAllowPackagesConfig = Field(default_factory=TyposquattingAllowPackagesConfig)
    allow_skill_names: list[str] = Field(default_factory=list)
    short_name_max_distance: int = 1
    medium_name_max_distance: int = 1
    long_name_max_distance: int = 2
    max_relative_distance: float = 0.2


class TemporalPolicyConfig(BaseModel):
    agent_directories: list[str] = Field(default_factory=lambda: list(DEFAULT_AGENT_DIRECTORIES))


class ScanConfig(BaseModel):
    device: str = "auto"
    scan_timeout_per_file: int = 30
    scan_timeout_total: int = 300
    layers: LayersConfig = Field(default_factory=LayersConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    chains: list[ChainConfig] = Field(default_factory=_default_chains)
    custom_rules: list[CustomRuleConfig] = Field(default_factory=list)
    trusted_urls: list[str] = Field(default_factory=list)
    frontmatter_policy: FrontmatterPolicyConfig = Field(default_factory=FrontmatterPolicyConfig)
    url_policy: URLPolicyConfig = Field(default_factory=URLPolicyConfig)
    typosquatting: TyposquattingConfig = Field(default_factory=TyposquattingConfig)
    temporal_policy: TemporalPolicyConfig = Field(default_factory=TemporalPolicyConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    model_cache_dir: str = "~/.skillinquisitor/models"
    default_format: str = "text"
    default_severity: Severity = Severity.LOW


class ScanResult(BaseModel):
    skills: list[Skill]
    findings: list[Finding] = Field(default_factory=list)
    risk_score: int = 100
    verdict: str = "SAFE"
    layer_metadata: dict[str, object] = Field(default_factory=dict)
    total_timing: float | None = None
