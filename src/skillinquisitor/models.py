from __future__ import annotations

from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


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
    ROT13_DECODE = "rot13_decode"
    FRONTMATTER_DESCRIPTION = "frontmatter_description"


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
    content: str
    segment_type: SegmentType = SegmentType.ORIGINAL
    location: Location = Field(default_factory=Location)
    provenance_chain: list[ProvenanceStep] = Field(default_factory=list)


class Artifact(BaseModel):
    path: str
    raw_content: str = ""
    normalized_content: str | None = None
    frontmatter: dict[str, object] = Field(default_factory=dict)
    file_type: FileType = FileType.UNKNOWN
    segments: list[Segment] = Field(default_factory=list)


class Skill(BaseModel):
    path: str = ""
    name: str | None = None
    artifacts: list[Artifact] = Field(default_factory=list)
    action_flags: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    severity: Severity = Severity.INFO
    category: Category = Category.STRUCTURAL
    layer: DetectionLayer = DetectionLayer.DETERMINISTIC
    rule_id: str = ""
    message: str = ""
    location: Location = Field(default_factory=Location)
    confidence: float | None = None
    action_flags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    details: dict[str, object] = Field(default_factory=dict)


class CheckConfig(BaseModel):
    enabled: bool = True
    checks: dict[str, bool] = Field(default_factory=dict)
    categories: dict[str, bool] = Field(default_factory=dict)


class WeightedModelConfig(BaseModel):
    id: str
    weight: float = 1.0
    type: str | None = None


class MLConfig(BaseModel):
    enabled: bool = True
    models: list[WeightedModelConfig] = Field(default_factory=list)
    threshold: float = 0.5


class LLMAPIConfig(BaseModel):
    provider: str | None = None
    model: str | None = None
    api_key_env: str | None = None


class LLMConfig(BaseModel):
    enabled: bool = True
    models: list[WeightedModelConfig] = Field(default_factory=list)
    deep_analysis: bool = False
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


class ChainConfig(BaseModel):
    name: str
    required: list[str]
    severity: Severity


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


class ScanConfig(BaseModel):
    device: str = "auto"
    scan_timeout_per_file: int = 30
    scan_timeout_total: int = 300
    layers: LayersConfig = Field(default_factory=LayersConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    chains: list[ChainConfig] = Field(default_factory=list)
    custom_rules: list[CustomRuleConfig] = Field(default_factory=list)
    trusted_urls: list[str] = Field(default_factory=list)
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
