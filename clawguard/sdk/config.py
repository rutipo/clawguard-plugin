"""SDK configuration via pydantic-settings."""

from pydantic_settings import BaseSettings


class ClawGuardConfig(BaseSettings):
    api_key: str = ""
    backend_url: str = "http://localhost:8000"
    flush_interval_seconds: float = 2.0
    enabled: bool = True
    log_to_stderr: bool = True
    capture_full_io: bool = False
    max_full_io_bytes: int = 50_000
    capture_timing: bool = True
    live_updates: bool = True

    model_config = {"env_prefix": "CLAWGUARD_", "env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}
