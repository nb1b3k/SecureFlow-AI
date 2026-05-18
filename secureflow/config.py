"""Load and validate `.secureflow.yml` into a typed Pydantic config.

Defaults are sane; every section is optional.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str = "secureflow"


class LLMConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    provider: Literal["gemini", "ollama", "groq", "openrouter", "deepseek"] = "gemini"
    # gemini-2.0-flash-lite gets a larger free-tier daily quota than
    # 2.5-flash-lite. Both support structured outputs. For provider=groq
    # / provider=openrouter the default below isn't used; those clients
    # pick their own defaults in the factory unless the user names a
    # provider-shaped model id explicitly.
    model: str = "gemini-2.0-flash-lite"
    # When the primary model returns daily-quota-exhausted, the cloud
    # client transparently switches to the next model in this list for
    # the remainder of the run. Free-tier quotas are per-model, so
    # falling back to a sibling model often keeps the scan moving.
    fallback_models: list[str] = Field(
        default_factory=lambda: ["gemini-2.5-flash-lite", "gemini-2.0-flash"]
    )
    # Cross-provider failover chain. When set, the factory wraps the
    # primary in a ChainLLMClient that tries each provider in order on
    # rate-limit / auth failure. Typical free-tier config:
    #   provider: gemini
    #   fallback_providers: [groq, openrouter]
    # Combined with `max_llm_concurrency: 1` this gives a near-bulletproof
    # path to a successful LLM-uplifted run across free tiers.
    fallback_providers: list[Literal["gemini", "groq", "openrouter", "ollama", "deepseek"]] = Field(
        default_factory=list
    )
    # Patch generation needs SIGNIFICANTLY higher output quality than
    # discovery / exploitability / threat-modeling. A bad exploitability
    # downgrade is recoverable (we just keep the original confidence); a
    # garbage patch silently corrupts the bot comment with replacement
    # code that looks like a mojibake salad.
    #
    # Pre-prod evidence: OpenRouter's free `deepseek-v4-flash:free`
    # returned 1,092 completion tokens of Chinese/Greek/math gibberish
    # when asked for a `PatchReplacement` JSON. Same model is fine for
    # the simpler discovery schema; structured-output reliability falls
    # apart on the patch task.
    #
    # When `patch_provider` is set, the patch agent builds a SEPARATE
    # chain from this provider + `patch_fallback_providers`. Otherwise
    # the patch agent falls back to the standard chain — preserving
    # backwards compatibility for users who haven't reconfigured.
    #
    # Default chain that ships in `.secureflow.yml`:
    #   patch_provider: deepseek                   # paid, V3, reliable JSON
    #   patch_fallback_providers: [gemini, groq]   # solid free fallbacks
    # We deliberately exclude OpenRouter free from the patch chain.
    patch_provider: Literal["gemini", "ollama", "groq", "openrouter", "deepseek"] | None = None
    patch_fallback_providers: list[Literal["gemini", "groq", "openrouter", "ollama", "deepseek"]] = Field(
        default_factory=list
    )
    temperature: float = 0.1
    # 4096 default — pre-prod eval surfaced occasional `Unterminated string`
    # JSON parse errors on DeepSeek when the model produced a long
    # `ThreatModelResponse` or `AIDiscoveryResponse` with many findings.
    # 2048 was enough for `PatchReplacement` (single-fix output) but too
    # tight for the multi-item array schemas; the model would hit the
    # cap mid-string and return truncated JSON. The chain failover and
    # corrective-retry both handle the failure gracefully, but at the
    # cost of extra latency + tokens. 4096 fits the longest observed
    # response (~3,200 tokens) with headroom.
    max_tokens: int = 4096
    cache: bool = True


class ScannerToggle(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    config: str | None = None  # e.g. semgrep config name


class ScannersConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    semgrep: ScannerToggle = Field(default_factory=lambda: ScannerToggle(config="auto"))
    gitleaks: ScannerToggle = Field(default_factory=ScannerToggle)
    grype: ScannerToggle = Field(default_factory=ScannerToggle)
    syft: ScannerToggle = Field(default_factory=ScannerToggle)
    bandit: ScannerToggle = Field(default_factory=lambda: ScannerToggle(enabled=False))
    # Static IaC scanner. Covers Terraform, Dockerfile, Docker Compose,
    # Kubernetes manifests, Helm charts, GitHub Actions workflows,
    # CloudFormation/Serverless, plus IAM and S3 bucket policy JSON
    # files that are committed to the repo. No live cloud access required.
    checkov: ScannerToggle = Field(default_factory=ScannerToggle)


class AIDiscoveryConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    run_on_all_prs: bool = False
    trigger_on_sensitive_files: bool = True
    sensitive_patterns: list[str] = Field(
        default_factory=lambda: [
            "auth", "login", "user", "admin", "payment", "billing",
            "permission", "role", "token", "session", "iam", "policy",
        ]
    )
    exclusion_paths: list[str] = Field(
        default_factory=lambda: [
            "tests/", "test/", "migrations/", "examples/", "docs/",
            "vendor/", "third_party/", "node_modules/",
        ]
    )


class ReachabilityConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    excluded_runtime_dirs: list[str] = Field(
        default_factory=lambda: [
            "tests", "test", "spec", "specs", "migrations", "alembic",
            "examples", "samples", "docs", "vendor", "third_party",
            "node_modules",
        ]
    )
    runtime_dirs: list[str] = Field(
        default_factory=lambda: [
            "app", "src", "routes", "handlers", "api", "services",
            "controllers", "lib",
        ]
    )
    enabled_languages: list[str] = Field(
        default_factory=lambda: ["python", "javascript", "typescript", "go"]
    )


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    # Policy profile governs how strictly the engine blocks CI.
    #
    # - `advisory`: never block. Every FAIL is reported as WARN. Useful
    #   for initial rollout, "shadow mode" runs, or repositories where the
    #   team wants visibility before enforcement.
    # - `balanced` (default): current behavior. Blocks on critical
    #   secrets, critical CVEs, high-confidence injection patterns, and
    #   AI-discovered critical findings with confidence >= 0.85.
    # - `strict`: tighter thresholds for security-sensitive repos. AI-
    #   discovered high findings can block at confidence >= 0.85, AI
    #   critical fails at >= 0.75, dependency-high CVEs with a fix block,
    #   and threat-model FAILs only need confidence >= 0.70.
    profile: Literal["advisory", "balanced", "strict"] = "balanced"
    fail_on: list[str] = Field(
        default_factory=lambda: [
            "critical_secret",
            "critical_cve",
            "high_confidence_injection",
            "confirmed_auth_bypass",
        ]
    )
    warn_on: list[str] = Field(
        default_factory=lambda: [
            "medium_ai_discovery",
            "low_confidence_high_impact",
            "outdated_dependency",
        ]
    )
    minimum_fail_confidence: float = 0.80
    minimum_warn_confidence: float = 0.50


class LimitsConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    max_changed_files_for_ai: int = 50
    max_findings_to_exploit_check: int = 30
    max_tokens_per_pr: int = 200_000
    max_llm_calls_per_pr: int = 50
    # Default 1 — serial LLM calls so no provider's per-minute / TPM cap
    # gets burst-tripped. With cross-provider failover (see
    # `llm.fallback_providers`) and per-client throttles already in
    # place, parallelism buys very little speed but multiplies the
    # chance of hitting rate limits on free tiers. Bump to 2-4 only on
    # paid tiers or local Ollama where bursting is safe.
    max_llm_concurrency: int = 1
    max_patch_concurrency: int = 2
    max_patches_per_pr: int = 10
    on_budget_exceeded: Literal["warn_and_skip_ai", "fail"] = "warn_and_skip_ai"


class ReportingConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    post_pr_comment: bool = True
    output_json: bool = True
    output_markdown: bool = True
    output_sarif: bool = True


class EnrichmentConfig(BaseModel):
    """External-API enrichment toggles. All optional and best-effort."""

    model_config = ConfigDict(extra="ignore")
    osv: bool = True               # OSV API for CVE/GHSA details (fast, no rate limit)
    # NVD off by default — free-tier rate limit is 5 req / 30s without an
    # API key, which serializes CVE enrichment and adds 10-30s of latency
    # to a scan with even a few CVEs. The shipped `.secureflow.yml` mirrors
    # this default. Set to `true` only when `NVD_API_KEY` is configured.
    nvd: bool = False              # NVD API for CVSS + descriptions
    mitre: bool = True             # CWE → ATT&CK static expansion (no network)
    cache_ttl_hours: int = 168     # 7 days
    # NVD without an API key rate-limits to ~5 req / 30s. Cap CVE enrichment
    # per PR. Bump this once `NVD_API_KEY` is in the env.
    max_cves_to_enrich: int = 5
    # Hard wall-clock ceiling for the whole enrichment node. If we hit it,
    # remaining CVEs go un-enriched but the pipeline continues.
    max_seconds: int = 45


class Config(BaseModel):
    """Top-level config. All sections optional."""

    model_config = ConfigDict(extra="ignore")
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    ai_discovery: AIDiscoveryConfig = Field(default_factory=AIDiscoveryConfig)
    reachability: ReachabilityConfig = Field(default_factory=ReachabilityConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig)


DEFAULT_PATH = ".secureflow.yml"


def load(path: str | Path | None = None) -> Config:
    """Load a config from `path` (default `.secureflow.yml`).

    Missing file → defaults. Invalid YAML → raises. Extra keys → ignored.
    """
    p = Path(path) if path else Path(DEFAULT_PATH)
    if not p.exists():
        return Config()
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{p}: top-level config must be a mapping, got {type(data).__name__}")
    return Config.model_validate(data)


def _clean_key(raw: str | None) -> str | None:
    """Normalize an API key read from the environment.

    Defensive against the BOM-in-secret class of bugs: when a GitHub
    Actions secret is set from a tool/editor that adds a UTF-8 BOM
    (or when a `gh secret set` invocation piped a BOM-prefixed string),
    the env value ends up as `﻿<actual key>`. The key then gets
    used as `Authorization: Bearer ﻿sk-...`, which Python's urllib
    tries to encode as latin-1 and crashes with "codec can't encode
    character '﻿' in position 7". The crash surfaces as an LLM
    error and silently downgrades the run.

    Strip the BOM (and surrounding whitespace) once at the boundary so
    every downstream caller is safe regardless of how the secret was
    set. Returns None for empty / whitespace-only values so the chain
    can still detect "key is missing" and skip the link gracefully.
    """
    if raw is None:
        return None
    cleaned = raw.lstrip("﻿").strip()
    return cleaned or None


def gemini_api_key() -> str | None:
    """Return the Gemini API key from env, or None if unset.

    We never read the key from the config file — keys live in the environment
    so they cannot accidentally be committed.
    """
    return _clean_key(os.environ.get("GEMINI_API_KEY"))


def gemini_model(cfg: Config) -> str:
    """Effective Gemini model: env override > config (if Gemini-shaped) > default.

    Critical for chain configs where `llm.model` is set for a DIFFERENT
    primary provider (e.g. `deepseek/deepseek-v4-flash:free` for an
    OpenRouter primary). In that case `cfg.llm.model` is meaningless to
    Gemini — we must fall through to a Gemini-native default instead of
    sending the OpenRouter id to Gemini and getting a 404.
    """
    env = os.environ.get("GEMINI_MODEL")
    if env:
        return env
    m = cfg.llm.model or ""
    if m.startswith("gemini-"):
        return m
    return "gemini-2.0-flash-lite"


def groq_api_key() -> str | None:
    """Return the Groq API key from env, or None if unset.

    Keys never live in the config file. Free key: https://console.groq.com/keys
    """
    return _clean_key(os.environ.get("GROQ_API_KEY"))


def openrouter_api_key() -> str | None:
    """Return the OpenRouter API key from env, or None if unset.

    The env name `OPENROUTER_AI_API_KEY` is what `.env.example` documents.
    A few users have it as `OPENROUTER_API_KEY` from older docs — we
    accept either to avoid silent misconfig.
    """
    return _clean_key(
        os.environ.get("OPENROUTER_AI_API_KEY") or os.environ.get("OPENROUTER_API_KEY")
    )


def openrouter_model(cfg: Config) -> str:
    """Effective OpenRouter model id."""
    env = os.environ.get("OPENROUTER_MODEL")
    if env:
        return env
    # Looks like an OpenRouter id when it has the `vendor/model` shape.
    if cfg.llm.model and "/" in cfg.llm.model:
        return cfg.llm.model
    return "deepseek/deepseek-v4-flash:free"


def deepseek_api_key() -> str | None:
    """Return the DeepSeek API key from env, or None if unset.

    DeepSeek is a *paid* provider (prepaid balance) used as the last link
    in the chain. Free-tier scans should never reach it; if it gets called,
    something upstream (Gemini/Groq/OpenRouter) was already exhausted.
    """
    return _clean_key(os.environ.get("DEEPSEEK_API_KEY"))


def deepseek_model(cfg: Config) -> str:
    """Effective DeepSeek model: env override > config (if DeepSeek-shaped) > default.

    `deepseek-chat` (V3) is the default — half the price of `deepseek-reasoner`
    and plenty for schema-validated security findings. Override via the env
    var if a specific run actually benefits from R1's reasoning chain.
    """
    env = os.environ.get("DEEPSEEK_MODEL")
    if env:
        return env
    m = cfg.llm.model or ""
    if m.startswith("deepseek-") and "/" not in m:
        return m
    return "deepseek-chat"


def groq_model(cfg: Config) -> str:
    """Effective Groq model: env override > config (if Groq-shaped) > default.

    Groq model ids look like `llama-3.1-8b-instant`, `gemma2-9b-it`, etc.
    They contain neither `gemini-` prefix nor a `/` separator. Anything
    else came from another provider's config and we must fall through to
    the Groq default — otherwise Groq returns HTTP 404 (`model_not_found`),
    which is exactly what blew up patch_generation in PR #2's earlier run.
    """
    env = os.environ.get("GROQ_MODEL")
    if env:
        return env
    m = cfg.llm.model or ""
    if m and not m.startswith("gemini-") and not m.startswith("deepseek-") and "/" not in m:
        return m
    # 8B-instant is the right free-tier default: ~30K TPM (vs 6K on the 70B
    # variant), enough headroom for a typical SecureFlow run. 70B is better
    # quality but its free-tier TPM is too tight; override via
    # `.secureflow.yml > llm.model` on paid tier.
    return "llama-3.1-8b-instant"
