"""Configuration loader — merges default.toml + local.toml + env vars."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib  # 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    merged = base.copy()
    for k, v in override.items():
        if k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = _deep_merge(merged[k], v)
        else:
            merged[k] = v
    return merged


@dataclass
class AIConfig:
    provider: str = "ollama"
    model: str = "deepseek-r1:70b"
    base_url: str = "http://localhost:11434"
    timeout_seconds: int = 120
    api_key: str = ""


@dataclass
class WebConfig:
    host: str = "127.0.0.1"
    port: int = 8000
    auth_enabled: bool = True
    api_key: str = ""


@dataclass
class FileIntegrityConfig:
    watch_paths: list[str] = field(default_factory=lambda: ["C:\\Windows\\System32\\drivers\\etc"])
    poll_interval_seconds: int = 30


@dataclass
class EDRConfig:
    enabled: bool = True
    plugins: list[str] = field(default_factory=lambda: ["sysmon", "process_monitor", "file_integrity"])
    file_integrity: FileIntegrityConfig = field(default_factory=FileIntegrityConfig)


@dataclass
class NetworkConfig:
    enabled: bool = True
    scan_range: str = "192.168.1.0/24"
    scan_interval_seconds: int = 60


@dataclass
class CorrelationConfig:
    enabled: bool = True
    window_seconds: int = 300
    min_chain_score: float = 7.0


@dataclass
class DatabaseConfig:
    path: str = "data/artemis.duckdb"


@dataclass
class Config:
    ai: AIConfig = field(default_factory=AIConfig)
    web: WebConfig = field(default_factory=WebConfig)
    edr: EDRConfig = field(default_factory=EDRConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    log_level: str = "info"

    @classmethod
    def load(cls, config_dir: Path | None = None) -> Config:
        """Load config from default.toml, overlay local.toml, then env vars."""
        if config_dir is None:
            config_dir = Path(__file__).parent.parent.parent.parent / "config"

        raw: dict[str, Any] = {}

        default_path = config_dir / "default.toml"
        if default_path.exists():
            with open(default_path, "rb") as f:
                raw = tomllib.load(f)

        local_path = config_dir / "local.toml"
        if local_path.exists():
            with open(local_path, "rb") as f:
                raw = _deep_merge(raw, tomllib.load(f))

        # Env overrides: ARTEMIS_AI__PROVIDER=openai → ai.provider
        prefix = "ARTEMIS_"
        for key, val in os.environ.items():
            if key.startswith(prefix):
                parts = key[len(prefix):].lower().split("__")
                d = raw
                for p in parts[:-1]:
                    d = d.setdefault(p, {})
                d[parts[-1]] = val

        return cls._from_dict(raw)

    @classmethod
    def _parse_edr(cls, data: dict[str, Any]) -> EDRConfig:
        fim_data = data.get("file_integrity", {})
        fim = FileIntegrityConfig(
            **{k: v for k, v in fim_data.items() if k in FileIntegrityConfig.__dataclass_fields__}
        )
        return EDRConfig(
            enabled=data.get("enabled", True),
            plugins=data.get("plugins", ["sysmon", "process_monitor", "file_integrity"]),
            file_integrity=fim,
        )

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> Config:
        general = data.get("general", {})
        return cls(
            ai=AIConfig(**{k: v for k, v in data.get("ai", {}).items() if k in AIConfig.__dataclass_fields__}),
            web=WebConfig(**{k: v for k, v in data.get("web", {}).items() if k in WebConfig.__dataclass_fields__}),
            edr=cls._parse_edr(data.get("edr", {})),
            network=NetworkConfig(**{k: v for k, v in data.get("network", {}).items() if k in NetworkConfig.__dataclass_fields__}),
            correlation=CorrelationConfig(**{k: v for k, v in data.get("correlation", {}).items() if k in CorrelationConfig.__dataclass_fields__}),
            database=DatabaseConfig(**{k: v for k, v in data.get("database", {}).items() if k in DatabaseConfig.__dataclass_fields__}),
            log_level=general.get("log_level", "info"),
        )
