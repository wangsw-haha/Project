from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.sql import func
from datetime import datetime
from typing import Optional
from src.core.config import config

Base = declarative_base()


class AttackLog(Base):
    """Attack log model"""
    __tablename__ = "attack_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    source_ip = Column(String(45), index=True)  # IPv4/IPv6
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(20), index=True)
    service = Column(String(50), index=True)
    attack_type = Column(String(100), index=True)
    payload = Column(Text)
    user_agent = Column(String(500))
    country = Column(String(2))
    city = Column(String(100))
    latitude = Column(Float)
    longitude = Column(Float)
    is_malicious = Column(Boolean, default=True)
    confidence_score = Column(Float)
    llm_analysis = Column(JSON)
    session_id = Column(String(100))
    duration = Column(Integer)  # Session duration in seconds
    commands_executed = Column(JSON)  # List of commands for SSH/Telnet
    files_accessed = Column(JSON)  # List of files accessed
    response_generated = Column(Text)  # LLM generated response
    severity = Column(String(20), default="medium")  # low, medium, high, critical
    
    def __repr__(self):
        return f"<AttackLog(id={self.id}, source_ip='{self.source_ip}', service='{self.service}')>"


class HoneypotSession(Base):
    """Honeypot session model"""
    __tablename__ = "honeypot_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(100), unique=True, index=True)
    source_ip = Column(String(45), index=True)
    service = Column(String(50), index=True)
    start_time = Column(DateTime(timezone=True), server_default=func.now())
    end_time = Column(DateTime(timezone=True))
    duration = Column(Integer)
    commands_count = Column(Integer, default=0)
    files_accessed_count = Column(Integer, default=0)
    bytes_transferred = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    
    def __repr__(self):
        return f"<HoneypotSession(id={self.id}, session_id='{self.session_id}', service='{self.service}')>"


class ThreatIntelligence(Base):
    """Threat intelligence model"""
    __tablename__ = "threat_intelligence"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True)
    is_malicious = Column(Boolean, default=False)
    threat_type = Column(String(100))
    source = Column(String(100))  # Source of intelligence (e.g., VirusTotal, AbuseIPDB)
    confidence = Column(Float)
    last_seen = Column(DateTime(timezone=True))
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    attack_count = Column(Integer, default=1)
    notes = Column(Text)
    
    def __repr__(self):
        return f"<ThreatIntelligence(ip='{self.ip_address}', malicious={self.is_malicious})>"


class SystemMetrics(Base):
    """System metrics model"""
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    disk_usage = Column(Float)
    network_in = Column(Integer)
    network_out = Column(Integer)
    active_connections = Column(Integer)
    attack_rate = Column(Float)  # Attacks per minute
    
    def __repr__(self):
        return f"<SystemMetrics(timestamp={self.timestamp}, cpu={self.cpu_usage}%)>"


# Database engine and session
engine = create_engine(
    config.database.url,
    echo=config.database.echo,
    pool_size=config.database.pool_size,
    max_overflow=config.database.max_overflow
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def create_tables():
    """Create all database tables"""
    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    """Get database session (non-generator version)"""
    return SessionLocal()