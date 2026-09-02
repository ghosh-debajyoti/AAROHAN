from fastapi import FastAPI

from app.api.routes import analyze
from app.core.database import Base, engine

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI-Powered Email Threat Detection API",
    description="MVP backend for parsing, analyzing, and scoring email threats.",
    version="1.0.0",
)

app.include_router(analyze.router, prefix="/api/v1", tags=["Analysis"])


@app.get("/")
def read_root():
    return {"message": "Welcome to the Email Threat Detection API"}
