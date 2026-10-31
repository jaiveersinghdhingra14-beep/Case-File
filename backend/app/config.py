from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "CaseFile v2: Big-Log Edition"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False

    # LLM Settings
    LLM_PROVIDER: str = "groq"
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    GEMINI_API_KEY: str = ""
    LLM_MODEL: str = "gemini-3.8-flash"
    USE_MOCK_LLM: bool = False
    MAX_LLM_CALLS: int = 200

    # Storage Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATABASE_PATH: str = "casefile_meta.db"
    PARQUET_STORAGE_DIR: str = "data/parquet"
    MAX_RAM_BUDGET_GB: float = 8.0

    # Tuning Defaults
    DEFAULT_CHUNK_SIZE: int = 20
    DEFAULT_SEED_TOP_K: int = 2000
    DEFAULT_EXPANSION_HOPS: int = 2
    DEFAULT_EXPANSION_WINDOW_SECONDS: int = 120
    DEFAULT_GROUP_GAP_SECONDS: int = 60

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def abs_db_path(self) -> Path:
        p = Path(self.DATABASE_PATH)
        return p if p.is_absolute() else self.BASE_DIR / p

    @property
    def abs_parquet_dir(self) -> Path:
        p = Path(self.PARQUET_STORAGE_DIR)
        return p if p.is_absolute() else self.BASE_DIR / p


settings = Settings()
