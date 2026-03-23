# config/settings.py
from pydantic import BaseSettings, Field, validator
from typing import List, Optional
from pathlib import Path


class SafetyConfig(BaseSettings):
    """Hardcoded safety controls - cannot be overridden by CLI/env"""
    allowed_targets: List[str] = Field(
        default=["localhost", "127.0.0.1", "0.0.0.0"],
        description="Domains/IPs allowed for testing"
    )
    dry_run_default: bool = Field(
        default=True,
        description="Default to dry-run mode for safety"
    )
    require_auth_confirmation: bool = Field(
        default=True,
        description="Require manual authorization for live runs"
    )

    @validator('allowed_targets')
    def validate_targets(cls, v):
        if not v:
            raise ValueError("allowed_targets cannot be empty")
        return [t.lower().strip() for t in v]


class ScanConfig(BaseSettings):
    """Configurable scan parameters"""
    target_url: str = Field(..., env="TARGET_URL")
    api_key: Optional[str] = Field(None, env="API_KEY")
    timeout_seconds: int = Field(default=30, ge=5, le=300)
    max_requests_per_minute: int = Field(default=60, ge=1, le=600)
    attack_types: List[str] = Field(
        default=["prompt_injection", "parameter_manipulation"],
        description="Which attack plugins to enable"
    )
    output_formats: List[str] = Field(
        default=["console", "json"],
        description="Report output formats"
    )

    @validator('target_url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError("target_url must be a valid HTTP(S) URL")
        return v.rstrip('/')


class Settings(BaseSettings):
    safety: SafetyConfig = SafetyConfig()
    scan: ScanConfig

    class Config:
        env_file = ".env"
        env_nested_delimiter = "__"
        case_sensitive = False


# Global settings instance
settings = Settings()