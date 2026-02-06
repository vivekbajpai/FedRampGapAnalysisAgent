"""
Configuration management for FedRamp Gap Analysis Agent.

This module handles all application configuration including environment variables,
database settings, API keys, and feature flags.
"""

import os
from typing import Optional, List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        env_parse_none_str="null",
    )
    
    # Application Settings
    app_name: str = Field(default="FedRamp Gap Analysis Agent", description="Application name")
    app_version: str = Field(default="1.0.0", description="Application version")
    environment: str = Field(default="development", description="Environment (development, staging, production)")
    debug: bool = Field(default=False, description="Debug mode")
    log_level: str = Field(default="INFO", description="Logging level")
    
    # API Settings
    api_host: str = Field(default="0.0.0.0", description="API host")
    api_port: int = Field(default=8000, description="API port")
    api_prefix: str = Field(default="/api/v1", description="API prefix")
    api_workers: int = Field(default=4, description="Number of API workers")
    
    # Security Settings
    secret_key: str = Field(default="change-me-in-production", description="Secret key for JWT")
    algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(default=30, description="Access token expiration")
    refresh_token_expire_days: int = Field(default=7, description="Refresh token expiration")
    
    # CORS Settings
    cors_origins: Union[str, List[str]] = Field(
        default="http://localhost:3000,http://localhost:8000",
        description="Allowed CORS origins"
    )
    cors_allow_credentials: bool = Field(default=True, description="Allow credentials")
    cors_allow_methods: Union[str, List[str]] = Field(default="*", description="Allowed methods")
    cors_allow_headers: Union[str, List[str]] = Field(default="*", description="Allowed headers")
    
    # Database Settings (SQLite by default for demo)
    database_url: str = Field(
        default="sqlite+aiosqlite:///./fedramp.db",
        description="Database connection URL"
    )
    database_pool_size: int = Field(default=10, description="Database connection pool size")
    database_max_overflow: int = Field(default=20, description="Database max overflow")
    database_echo: bool = Field(default=False, description="Echo SQL queries")
    
    # Redis Settings (Optional - disabled by default for demo)
    redis_url: Optional[str] = Field(default=None, description="Redis connection URL (optional)")
    redis_cache_ttl: int = Field(default=3600, description="Redis cache TTL in seconds")
    redis_max_connections: int = Field(default=50, description="Redis max connections")
    
    # IBM watsonx.ai Settings
    wxo_api_key: Optional[str] = Field(default=None, description="IBM Cloud API key")
    wxo_project_id: Optional[str] = Field(default=None, description="watsonx.ai project ID")
    wxo_url: str = Field(
        default="https://us-south.ml.cloud.ibm.com",
        description="watsonx.ai API URL"
    )
    wxo_model_id: str = Field(
        default="ibm/granite-13b-chat-v2",
        description="watsonx.ai model ID"
    )
    wxo_max_tokens: int = Field(default=2048, description="Max tokens for generation")
    wxo_temperature: float = Field(default=0.7, description="Temperature for generation")
    wxo_timeout: int = Field(default=300, description="API timeout in seconds")
    
    # Git Settings
    git_clone_dir: str = Field(default="./temp/repos", description="Directory for cloned repos")
    git_max_repo_size_mb: int = Field(default=500, description="Max repository size in MB")
    git_timeout: int = Field(default=300, description="Git operation timeout")
    
    # Confluence Settings
    confluence_url: Optional[str] = Field(default=None, description="Confluence base URL")
    confluence_username: Optional[str] = Field(default=None, description="Confluence username")
    confluence_api_token: Optional[str] = Field(default=None, description="Confluence API token")
    confluence_space_key: Optional[str] = Field(default=None, description="Confluence space key")
    
    # Analysis Settings
    max_file_size_mb: int = Field(default=50, description="Max file size for analysis")
    max_concurrent_analyses: int = Field(default=5, description="Max concurrent analyses")
    analysis_timeout: int = Field(default=1800, description="Analysis timeout in seconds")
    enable_caching: bool = Field(default=True, description="Enable result caching")
    
    # Report Settings
    report_output_dir: str = Field(default="./reports", description="Report output directory")
    report_formats: Union[str, List[str]] = Field(
        default="json,pdf,html,excel",
        description="Supported report formats"
    )
    
    # Rate Limiting
    rate_limit_enabled: bool = Field(default=True, description="Enable rate limiting")
    rate_limit_requests: int = Field(default=100, description="Max requests per window")
    rate_limit_window: int = Field(default=60, description="Rate limit window in seconds")
    
    # Feature Flags
    enable_pdf_parsing: bool = Field(default=True, description="Enable PDF parsing")
    enable_docx_parsing: bool = Field(default=True, description="Enable DOCX parsing")
    enable_confluence: bool = Field(default=True, description="Enable Confluence integration")
    enable_git_analysis: bool = Field(default=True, description="Enable Git repository analysis")
    enable_java_analysis: bool = Field(default=True, description="Enable Java code analysis")
    enable_dependency_check: bool = Field(default=True, description="Enable dependency checking")
    enable_wxo_integration: bool = Field(default=True, description="Enable watsonx.ai integration")
    
    # Monitoring & Observability
    enable_metrics: bool = Field(default=True, description="Enable Prometheus metrics")
    enable_tracing: bool = Field(default=False, description="Enable distributed tracing")
    metrics_port: int = Field(default=9090, description="Metrics endpoint port")
    
    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v):
        """Validate environment value."""
        allowed = ["development", "staging", "production"]
        if v not in allowed:
            raise ValueError(f"Environment must be one of {allowed}")
        return v
    
    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v):
        """Validate log level."""
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed:
            raise ValueError(f"Log level must be one of {allowed}")
        return v.upper()
    
    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse CORS origins from string or list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v if isinstance(v, list) else [v]
    
    @field_validator("cors_allow_methods", mode="before")
    @classmethod
    def parse_cors_methods(cls, v):
        """Parse CORS methods from string or list."""
        if isinstance(v, str):
            return [method.strip() for method in v.split(",") if method.strip()]
        return v if isinstance(v, list) else [v]
    
    @field_validator("cors_allow_headers", mode="before")
    @classmethod
    def parse_cors_headers(cls, v):
        """Parse CORS headers from string or list."""
        if isinstance(v, str):
            return [header.strip() for header in v.split(",") if header.strip()]
        return v if isinstance(v, list) else [v]
    
    @field_validator("report_formats", mode="before")
    @classmethod
    def parse_report_formats(cls, v):
        """Parse report formats from string or list."""
        if isinstance(v, str):
            return [fmt.strip() for fmt in v.split(",") if fmt.strip()]
        return v if isinstance(v, list) else [v]
    
    def get_cors_origins(self) -> List[str]:
        """Get CORS origins as list."""
        if isinstance(self.cors_origins, str):
            return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
        return self.cors_origins
    
    def get_cors_methods(self) -> List[str]:
        """Get CORS methods as list."""
        if isinstance(self.cors_allow_methods, str):
            return [method.strip() for method in self.cors_allow_methods.split(",") if method.strip()]
        return self.cors_allow_methods
    
    def get_cors_headers(self) -> List[str]:
        """Get CORS headers as list."""
        if isinstance(self.cors_allow_headers, str):
            return [header.strip() for header in self.cors_allow_headers.split(",") if header.strip()]
        return self.cors_allow_headers
    
    def get_report_formats(self) -> List[str]:
        """Get report formats as list."""
        if isinstance(self.report_formats, str):
            return [fmt.strip() for fmt in self.report_formats.split(",") if fmt.strip()]
        return self.report_formats
    
    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.environment == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development."""
        return self.environment == "development"
    
    def get_database_url(self, async_driver: bool = False) -> str:
        """Get database URL with optional async driver."""
        if async_driver:
            return self.database_url.replace("postgresql://", "postgresql+asyncpg://")
        return self.database_url


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings instance."""
    return settings


def reload_settings() -> Settings:
    """Reload settings from environment."""
    global settings
    settings = Settings()
    return settings

# Made with Bob
