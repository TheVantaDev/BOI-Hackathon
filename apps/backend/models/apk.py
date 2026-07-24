import uuid
from datetime import datetime, timezone
from typing import Optional, Any

from sqlalchemy import Column, String, Float, Text, DateTime, BigInteger, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from pydantic import BaseModel

from services.db import Base


class APKUpload(Base):
    __tablename__ = "apk_uploads"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    filename = Column(String(255), nullable=False)
    sha256 = Column(String(64), unique=True, nullable=False)
    file_size = Column(BigInteger)
    upload_time = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    status = Column(String(50), default="pending")
    minio_path = Column(String(500))

    analysis = relationship("AnalysisResult", back_populates="apk", uselist=False, cascade="all, delete-orphan")
    report = relationship("RiskReport", back_populates="apk", uselist=False, cascade="all, delete-orphan")


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    apk_id = Column(UUID(as_uuid=True), ForeignKey("apk_uploads.id", ondelete="CASCADE"), nullable=False)
    static_analysis = Column(JSONB)
    dynamic_analysis = Column(JSONB)
    threat_intel = Column(JSONB)
    ai_summary = Column(Text)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    apk = relationship("APKUpload", back_populates="analysis")


class RiskReport(Base):
    __tablename__ = "risk_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    apk_id = Column(UUID(as_uuid=True), ForeignKey("apk_uploads.id", ondelete="CASCADE"), nullable=False)
    risk_score = Column(Float)
    severity = Column(String(50))
    classification = Column(String(100))
    fraud_intent = Column(String(200))
    fraud_journey = Column(JSONB)
    executive_summary = Column(Text)
    recommendations = Column(JSONB)
    mitre_mappings = Column(JSONB)
    shap_explanations = Column(JSONB)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    apk = relationship("APKUpload", back_populates="report")


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    apk_id = Column(UUID(as_uuid=True), ForeignKey("apk_uploads.id", ondelete="CASCADE"), nullable=False)
    indicator_type = Column(String(100))
    indicator_value = Column(Text)
    source = Column(String(100))
    severity = Column(String(50))
    mitre_technique = Column(String(50))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# Pydantic schemas

class APKUploadOut(BaseModel):
    id: str
    filename: str
    sha256: str
    file_size: Optional[int]
    upload_time: datetime
    status: str
    minio_path: Optional[str]

    class Config:
        from_attributes = True


class AnalysisOut(BaseModel):
    apk_id: str
    filename: str
    sha256: str
    status: str
    upload_time: datetime
    static_analysis: Optional[Any]
    dynamic_analysis: Optional[Any]
    threat_intel: Optional[Any]
    ai_summary: Optional[str]


class RiskReportOut(BaseModel):
    apk_id: str
    risk_score: Optional[float]
    severity: Optional[str]
    classification: Optional[str]
    fraud_intent: Optional[str]
    fraud_journey: Optional[Any]
    executive_summary: Optional[str]
    recommendations: Optional[Any]
    mitre_mappings: Optional[Any]
    shap_explanations: Optional[Any]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True
