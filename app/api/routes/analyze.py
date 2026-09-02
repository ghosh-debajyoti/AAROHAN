import re
import traceback
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.domain import Case, EmailEvidence
from app.schemas.domain import UCOCaseResponse
from app.services.dna_service import DnaService
from app.services.evidence_service import EvidenceService
from app.services.forensic_service import ForensicEngineService
from app.services.graph_service import GraphService
from app.services.intel_service import IntelService
from app.services.parser_service import EmailParserService
from app.services.threat_scoring_service import ThreatScoringService
from app.services.translator_service import TranslatorService

router = APIRouter()

@router.post("/analyze", response_model=UCOCaseResponse)
async def analyze_email(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")
        
    try:
        raw_bytes = await file.read()
        
        # 1. Parse Email
        parsed = EmailParserService(raw_bytes).parse_all()
        
        # 2. Forensics & Threat Score
        alignment = ForensicEngineService(parsed.headers).evaluate_alignment()
        final_score = ThreatScoringService(parsed.body, alignment["technical_flag_score"]).generate_final_score()
        
        # 3. TLSH DNA
        tlsh_hash = DnaService.generate_hash(parsed.body)
        sim_score, is_coordinated = DnaService.correlate_tlsh(db, tlsh_hash)
        
        # 4. Intelligence
        infra_intel = {}
        if parsed.relay_route and parsed.relay_route[0].get("ip"):
            infra_intel = IntelService.query_ip(parsed.relay_route[0]["ip"])
            
        from_dom = re.search(r'@([\w.-]+)', str(parsed.headers.get("From") or ""))
        reply_dom = re.search(r'@([\w.-]+)', str(parsed.headers.get("Reply-To") or ""))
        lookalikes = []
        if from_dom and reply_dom:
            res = IntelService.check_lookalike_domain(from_dom.group(1), reply_dom.group(1))
            if res.get("is_lookalike"):
                lookalikes.append(res)
                
        # 5. Graph
        graph = GraphService.generate_stix_graph(parsed.indicators, infra_intel, is_coordinated)
        
        # 6. Database Records
        case_number = f"CAS-{uuid.uuid4().hex[:8].upper()}"
        db_case = Case(
            case_number=case_number,
            threat_score=final_score,
            status="open",
            infrastructure=infra_intel,
            relay_route=parsed.relay_route,
            stix_graph=graph
        )
        db.add(db_case)
        db.flush()
        
        sha256_hash = EvidenceService.generate_hash(raw_bytes)
        def clean_header(val):
            if val is None: return None
            if isinstance(val, list): return str(val[0])
            return str(val)

        db_evidence = EmailEvidence(
            case_id=db_case.id,
            sender=clean_header(parsed.headers.get("From")),
            reply_to=clean_header(parsed.headers.get("Reply-To")),
            subject=clean_header(parsed.headers.get("Subject")),
            received_date=clean_header(parsed.headers.get("Date")),
            evidence_hash=sha256_hash,
            tlsh_hash=tlsh_hash
        )
        db.add(db_evidence)
        db.commit()
        db.refresh(db_case)
        
        # 7. Translator to UCO
        uco_format = TranslatorService.map_to_uco(
            headers=parsed.headers,
            relay_route=parsed.relay_route,
            indicators=parsed.indicators,
            attachments=[{"filename": a.filename, "size": a.size, "sha256": a.sha256} for a in parsed.attachments],
            mime_boundaries=parsed.mime_boundaries,
            tlsh_hash=tlsh_hash,
            threat_score=final_score,
            technical_flags=alignment,
            lookalikes=lookalikes,
            is_coordinated=is_coordinated,
            sha256_hash=sha256_hash
        )
        
        return {
            "id": db_case.id,
            "case_number": db_case.case_number,
            "status": db_case.status,
            "created_at": db_case.created_at,
            **uco_format,
            "graph": graph
        }

    except Exception as e:
        db.rollback()
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An error occurred during analysis: {e!s}")
