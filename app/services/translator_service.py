from typing import Any

from app.schemas.domain import (
    AssertionBase,
    EvidenceCustodyBase,
    PropertyBase,
    TraceBase,
)


class TranslatorService:
    @staticmethod
    def map_to_uco(headers: dict[str, Any], relay_route: list[dict[str, Any]], 
                   indicators: list[dict[str, Any]], attachments: list[dict[str, Any]], 
                   mime_boundaries: list[str], tlsh_hash: str, 
                   threat_score: float, technical_flags: dict[str, Any], 
                   lookalikes: list[dict[str, Any]], is_coordinated: bool, 
                   sha256_hash: str) -> dict[str, Any]:
                   
        trace = TraceBase(headers=headers, relay_route=relay_route)
        prop = PropertyBase(indicators=indicators, attachments=attachments, mime_boundaries=mime_boundaries, tlsh_hash=tlsh_hash)
        assertion = AssertionBase(threat_score=threat_score, is_coordinated_campaign=is_coordinated, lookalikes=lookalikes, technical_flags=technical_flags)
        evidence = EvidenceCustodyBase(sha256_hash=sha256_hash)
        
        return {
            "trace": trace.model_dump(),
            "property": prop.model_dump(),
            "assertion": assertion.model_dump(),
            "evidence_custody": evidence.model_dump()
        }
