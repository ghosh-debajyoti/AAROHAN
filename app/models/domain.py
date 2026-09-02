import datetime

from sqlalchemy import JSON, Column, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_number = Column(String, unique=True, index=True)
    threat_score = Column(Float)
    status = Column(String, default="open")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    infrastructure = Column(JSON, nullable=True)
    relay_route = Column(JSON, nullable=True)
    stix_graph = Column(JSON, nullable=True)

    evidence = relationship("EmailEvidence", back_populates="case", uselist=False)
    indicators = relationship("Indicator", back_populates="case")


class EmailEvidence(Base):
    __tablename__ = "email_evidence"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"))
    sender = Column(String)
    reply_to = Column(String)
    subject = Column(String)
    received_date = Column(String)
    evidence_hash = Column(String)
    tlsh_hash = Column(String, nullable=True)

    case = relationship("Case", back_populates="evidence")


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"))
    type = Column(String)  # IP, URL, DOMAIN
    value = Column(String)
    malicious_confidence = Column(Float)

    case = relationship("Case", back_populates="indicators")
