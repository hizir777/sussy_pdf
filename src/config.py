"""
Application Configuration Management (v1.1.0+)

Centralized settings from .env file
"""


from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings from environment variables."""
    
    # ============================================
    # API & Server
    # ============================================
    
    server_host: str = Field("0.0.0.0", env="SERVER_HOST")
    server_port: int = Field(8443, env="SERVER_PORT")
    debug: bool = Field(False, env="DEBUG")
    reload: bool = Field(False, env="RELOAD")
    
    # ============================================
    # Authentication & Security
    # ============================================
    
    api_key_secret: str = Field(
        "dev-secret-key-change-in-production",
        env="API_KEY_SECRET"
    )
    jwt_secret: str = Field(
        "dev-secret-key-change-in-production",
        env="JWT_SECRET"
    )
    jwt_algorithm: str = Field("HS256", env="JWT_ALGORITHM")
    jwt_expiration_hours: int = Field(24, env="JWT_EXPIRATION_HOURS")
    
    # ============================================
    # CORS & Rate Limiting
    # ============================================
    
    cors_origins: list[str] = Field(
        ["http://localhost:8443", "http://localhost:3000"],
        env="CORS_ORIGINS"
    )
    cors_allow_credentials: bool = Field(True, env="CORS_ALLOW_CREDENTIALS")
    
    rate_limit_enabled: bool = Field(True, env="RATE_LIMIT_ENABLED")
    rate_limit_per_minute: int = Field(60, env="RATE_LIMIT_PER_MINUTE")
    rate_limit_per_hour: int = Field(600, env="RATE_LIMIT_PER_HOUR")
    
    # ============================================
    # File Handling
    # ============================================
    
    work_dir: str = Field("./output", env="WORK_DIR")
    temp_dir: str = Field("./temp", env="TEMP_DIR")
    pdf_upload_dir: str = Field("./uploads", env="PDF_UPLOAD_DIR")
    log_dir: str = Field("./logs", env="LOG_DIR")
    
    max_file_size_mb: int = Field(500, env="MAX_FILE_SIZE_MB")
    max_batch_size: int = Field(100, env="MAX_BATCH_SIZE")
    
    # ============================================
    # Analysis Settings
    # ============================================
    
    analysis_timeout: int = Field(300, env="ANALYSIS_TIMEOUT")
    upload_timeout: int = Field(60, env="UPLOAD_TIMEOUT")
    stream_decode_timeout: int = Field(30, env="STREAM_DECODE_TIMEOUT")
    
    js_emulation_enabled: bool = Field(True, env="JS_EMULATION_ENABLED")
    js_sandbox_enabled: bool = Field(True, env="JS_SANDBOX_ENABLED")
    anti_evasion_check: bool = Field(True, env="ANTI_EVASION_CHECK")
    
    # ============================================
    # YARA & Threat Intelligence
    # ============================================
    
    yara_rules_path: str = Field("./specs/yara_rules", env="YARA_RULES_PATH")
    yara_scan_enabled: bool = Field(True, env="YARA_SCAN_ENABLED")
    
    virustotal_api_key: str = Field("", env="VIRUSTOTAL_API_KEY")
    virustotal_rate_limit: int = Field(4, env="VIRUSTOTAL_RATE_LIMIT")
    
    # ============================================
    # Reporting
    # ============================================
    
    output_formats: str = Field("json,html", env="OUTPUT_FORMATS")
    report_language: str = Field("en", env="REPORT_LANGUAGE")
    
    # ============================================
    # Logging
    # ============================================
    
    log_level: str = Field("INFO", env="LOG_LEVEL")
    log_format: str = Field("json", env="LOG_FORMAT")
    log_file: str = Field("./logs/sussy_pdf.log", env="LOG_FILE")
    log_max_size_mb: int = Field(100, env="LOG_MAX_SIZE_MB")
    log_backup_count: int = Field(5, env="LOG_BACKUP_COUNT")
    
    # ============================================
    # Database (Future)
    # ============================================
    
    sqlite_db_path: str = Field("./data/sussy_pdf.db", env="SQLITE_DB_PATH")
    database_url: str = Field("", env="DATABASE_URL")
    
    class Config:
        """Pydantic config."""
        env_file = ".env"
        case_sensitive = False
    
    def get_max_file_size_bytes(self) -> int:
        """Get max file size in bytes."""
        return self.max_file_size_mb * 1024 * 1024
    
    def get_output_formats(self) -> list[str]:
        """Get list of output formats."""
        return [fmt.strip() for fmt in self.output_formats.split(',')]
    
    def get_cors_origins(self) -> list[str]:
        """Get CORS origins as list."""
        if isinstance(self.cors_origins, str):
            import json
            try:
                return json.loads(self.cors_origins)
            except Exception:
                return self.cors_origins.split(',')
        return self.cors_origins


# Global settings instance
settings = Settings()
