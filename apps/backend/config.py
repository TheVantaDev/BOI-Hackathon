from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://sentinel:sentinel_pass@localhost:5432/sentinel_db"

    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "sentinel_minio"
    minio_secret_key: str = "sentinel_minio_pass"
    minio_bucket: str = "apk-uploads"

    static_analysis_url: str = "http://localhost:8010"
    dynamic_analysis_url: str = "http://localhost:8011"
    threat_intel_url: str = "http://localhost:8012"
    rag_engine_url: str = "http://localhost:8013"
    ai_engine_url: str = "http://localhost:8014"
    fraud_engine_url: str = "http://localhost:8015"
    risk_scoring_url: str = "http://localhost:8016"

    class Config:
        env_file = ".env"


settings = Settings()
