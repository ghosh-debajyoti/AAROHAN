import hashlib


class EvidenceService:
    @staticmethod
    def generate_hash(raw_bytes: bytes) -> str:
        return hashlib.sha256(raw_bytes).hexdigest()
