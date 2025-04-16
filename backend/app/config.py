from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    GRAPH_DB_URI_PYPI: str = ""
    GRAPH_DB_URI_NPM: str = ""
    GRAPH_DB_URI_MAVEN: str = ""
    GRAPH_DB_URI_CARGO: str = ""
    GRAPH_DB_URI_NUGET: str = ""
    VULN_DB_URI: str = ""
    GRAPH_DB_USER: str = ""
    GRAPH_DB_PASSWORD_PYPI: str = ""
    GRAPH_DB_PASSWORD_NPM: str = ""
    GRAPH_DB_PASSWORD_MAVEN: str = ""
    GRAPH_DB_PASSWORD_CARGO: str = ""
    GRAPH_DB_PASSWORD_NUGET: str = ""
    VULN_DB_USER: str = ""
    VULN_DB_PASSWORD: str = ""
    ALGORITHM: str = ""
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 0
    JWT_SECRET_KEY: str = ""
    GITHUB_GRAPHQL_API_KEY: str = ""
    NVD_API_KEY: str = ""
    GUAC_IMAGE: str = ""
    GUAC_API_PORT: str = ""
    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
