"""Runtime configuration — environment variables only. No secrets are hardcoded or logged."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv() -> None:
    """Minimal .env loader (no dependency). Existing environment variables win."""
    for candidate in (Path.cwd() / ".env", Path(__file__).resolve().parents[2] / ".env"):
        if not candidate.is_file():
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
        break


def default_env_file() -> Path:
    """The .env the loader reads (current directory first, else the project root). Also where the UI saves integrations."""
    if os.environ.get("GHOST_ENV_FILE"):
        return Path(os.environ["GHOST_ENV_FILE"])
    cwd = Path.cwd() / ".env"
    return cwd if cwd.is_file() else Path(__file__).resolve().parents[2] / ".env"


_load_dotenv()


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("GHOST_DATA_DIR", "")) if os.environ.get("GHOST_DATA_DIR") else Path(__file__).resolve().parents[2] / "data")
    host: str = field(default_factory=lambda: os.environ.get("GHOST_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _int("GHOST_PORT", 8787))
    cors_origins: list[str] = field(default_factory=lambda: [o.strip() for o in os.environ.get("GHOST_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()])

    # Outbound HTTP safety
    http_timeout: float = field(default_factory=lambda: float(os.environ.get("GHOST_HTTP_TIMEOUT", "8")))
    max_redirects: int = field(default_factory=lambda: _int("GHOST_MAX_REDIRECTS", 4))
    max_response_bytes: int = field(default_factory=lambda: _int("GHOST_MAX_RESPONSE_BYTES", 262144))
    # Escape hatch for local lab testing ONLY. Disabled by default.
    allow_private_targets: bool = field(default_factory=lambda: os.environ.get("GHOST_ALLOW_PRIVATE_TARGETS", "0") == "1")

    # Evidence / PCAP
    max_upload_mb: int = field(default_factory=lambda: _int("GHOST_MAX_UPLOAD_MB", 200))
    pcap_timeout: int = field(default_factory=lambda: _int("GHOST_PCAP_TIMEOUT", 120))
    vault_passphrase: str | None = field(default_factory=lambda: os.environ.get("GHOST_VAULT_PASSPHRASE") or None)

    # Map
    map_tile_url: str = field(default_factory=lambda: os.environ.get("GHOST_MAP_TILE_URL", ""))
    map_attribution: str = field(default_factory=lambda: os.environ.get("GHOST_MAP_ATTRIBUTION", "Natural Earth (public domain) · bundled vector basemap"))

    # Set to 1 if your tile provider already serves a dark style (otherwise tiles are darkened client-side)
    map_dark_tiles: bool = field(default_factory=lambda: os.environ.get("GHOST_MAP_DARK_TILES", "0") == "1")

    # Threat-intel providers (keys never leave the backend)
    vt_api_key: str | None = field(default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY") or None)
    abuseipdb_api_key: str | None = field(default_factory=lambda: os.environ.get("ABUSEIPDB_API_KEY") or None)
    ipinfo_token: str | None = field(default_factory=lambda: os.environ.get("IPINFO_TOKEN") or None)

    # Optional AI analyst (OpenAI-compatible endpoint; a local Ollama server works)
    ai_base_url: str | None = field(default_factory=lambda: os.environ.get("GHOST_AI_BASE_URL") or None)
    ai_model: str | None = field(default_factory=lambda: os.environ.get("GHOST_AI_MODEL") or None)
    ai_api_key: str | None = field(default_factory=lambda: os.environ.get("GHOST_AI_API_KEY") or None)

    # Optional tools
    tshark_path: str | None = field(default_factory=lambda: os.environ.get("GHOST_TSHARK_PATH") or None)
    zeek_path: str | None = field(default_factory=lambda: os.environ.get("GHOST_ZEEK_PATH") or None)

    env_file: Path = field(default_factory=default_env_file)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "ghost.db"

    @property
    def vault_dir(self) -> Path:
        return self.data_dir / "vault"

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def report_dir(self) -> Path:
        return self.data_dir / "reports"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.vault_dir, self.upload_dir, self.report_dir):
            d.mkdir(parents=True, exist_ok=True)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings(**overrides) -> Settings:
    """Replace the global settings (used by tests and the CLI)."""
    global _settings
    _settings = Settings(**overrides)
    return _settings
