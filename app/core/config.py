import os


class Settings:
    # Defaulting to an in-memory SQLite database for easy MVP testing if no Postgres is provided
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./mvp.db")


settings = Settings()
