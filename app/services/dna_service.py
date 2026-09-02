
import tlsh
from sqlalchemy.orm import Session

from app.models.domain import EmailEvidence


class DnaService:
    @staticmethod
    def generate_hash(body_text: str) -> str:
        if not body_text or len(body_text) < 50:
            return ""
        try:
            return tlsh.hash(body_text.encode('utf-8'))
        except Exception:
            return ""

    @staticmethod
    def correlate_tlsh(db: Session, current_hash: str) -> tuple[float, bool]:
        if not current_hash:
            return 0.0, False
            
        historical_evidences = db.query(EmailEvidence).filter(EmailEvidence.tlsh_hash.isnot(None)).all()
        max_similarity_score = 0.0
        
        for ev in historical_evidences:
            if ev.tlsh_hash == current_hash:
                continue
            try:
                diff = tlsh.diff(current_hash, ev.tlsh_hash)
                score = 100 - diff if diff <= 100 else 0
                max_similarity_score = max(max_similarity_score, score)
            except Exception:
                pass
                
        is_coordinated = max_similarity_score > 80
        return max_similarity_score, is_coordinated
