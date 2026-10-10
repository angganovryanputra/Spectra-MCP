"""
Spectra MCP - Database Models and Engine
SQLAlchemy SQLite Persistence Layer with WAL mode, Multi-Project Scoping, Guardrails, and AI Reasoning
"""

import os
import json
from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    desc,
    event
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

DB_PATH = os.getenv("SPECTRA_DB_PATH", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "spectra.db"))
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)

# Enable SQLite WAL (Write-Ahead Logging) and busy_timeout for concurrency & persistence
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Scope & Guardrail settings
    scope_enabled = Column(Boolean, default=False)
    allowed_hosts = Column(Text, default="[\"*\"]")  # JSON List, e.g. ["*.target.local", "127.0.0.1"]
    blocked_patterns = Column(Text, default="[\"logout\", \"delete.*user\", \"payment\", \"stripe\", \"checkout\"]")  # JSON List
    
    # Rate Limiting & Proxy Chaining settings
    delay_ms = Column(Integer, default=0)  # Throttling delay between requests in milliseconds
    upstream_proxy = Column(String(255), default="")  # e.g. http://127.0.0.1:8080 (Burp Suite / Caido / ZAP)

    def to_dict(self):
        try:
            allowed = json.loads(self.allowed_hosts) if self.allowed_hosts else ["*"]
        except Exception:
            allowed = ["*"]
        try:
            blocked = json.loads(self.blocked_patterns) if self.blocked_patterns else []
        except Exception:
            blocked = []

        return {
            "id": self.id,
            "name": self.name,
            "description": self.description or "",
            "created_at": self.created_at.isoformat() if self.created_at else "",
            "scope_enabled": bool(self.scope_enabled),
            "allowed_hosts": allowed,
            "blocked_patterns": blocked,
            "delay_ms": self.delay_ms or 0,
            "upstream_proxy": self.upstream_proxy or ""
        }


class HttpLog(Base):
    __tablename__ = "http_logs"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    project = Column(String(100), default="default", index=True)
    agent_id = Column(String(100), default="primary_agent", index=True)  # Multi-Agent Tag
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source = Column(String(32), default="HTTP_CLIENT")  # HTTP_CLIENT, BROWSER_RENDER, REPEATER, FUZZER
    method = Column(String(16), default="GET", index=True)
    url = Column(Text, nullable=False)
    host = Column(String(255), index=True)
    path = Column(Text, nullable=False)
    status_code = Column(Integer, nullable=True, index=True)
    duration_ms = Column(Integer, default=0)
    request_headers = Column(Text, default="{}")  # JSON String
    request_body = Column(Text, default="")
    response_headers = Column(Text, default="{}")  # JSON String
    response_body = Column(Text, default="")
    flag_status = Column(String(32), default="CLEAN", index=True)  # CLEAN, POTENTIAL, CONFIRMED, BLOCKED
    reasoning = Column(Text, nullable=True, default="")  # AI Agent Hypothesis / Intent

    findings = relationship("Finding", back_populates="log", cascade="all, delete-orphan", lazy="joined")

    def to_dict(self, include_body: bool = True):
        try:
            req_headers = json.loads(self.request_headers) if self.request_headers else {}
        except Exception:
            req_headers = {"raw": self.request_headers}

        try:
            res_headers = json.loads(self.response_headers) if self.response_headers else {}
        except Exception:
            res_headers = {"raw": self.response_headers}

        data = {
            "id": self.id,
            "project": self.project or "default",
            "agent_id": self.agent_id or "primary_agent",
            "timestamp": self.timestamp.isoformat() if self.timestamp else "",
            "source": self.source,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "status_code": self.status_code,
            "duration_ms": self.duration_ms,
            "request_headers": req_headers,
            "response_headers": res_headers,
            "flag_status": self.flag_status,
            "reasoning": self.reasoning or "",
            "findings": [f.to_dict() for f in (self.findings or [])]
        }
        if include_body:
            data["request_body"] = self.request_body
            data["response_body"] = self.response_body
        return data


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    log_id = Column(Integer, ForeignKey("http_logs.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    category = Column(String(255), nullable=False, index=True)
    evidence = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)

    log = relationship("HttpLog", back_populates="findings")

    def to_dict(self):
        return {
            "id": self.id,
            "log_id": self.log_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation
        }


class ActiveSession(Base):
    __tablename__ = "active_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project = Column(String(100), default="default", index=True)
    domain = Column(String(255), index=True, nullable=False)
    storage_state = Column(Text, nullable=False, default="{}")  # Cookies, LocalStorage, SessionStorage
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        try:
            state = json.loads(self.storage_state)
        except Exception:
            state = {}
        cookies = state.get("cookies", [])
        return {
            "id": self.id,
            "project": self.project or "default",
            "domain": self.domain,
            "cookie_count": len(cookies),
            "cookies": cookies,
            "updated_at": self.updated_at.isoformat() if self.updated_at else ""
        }


def _run_migrations():
    """Safely adds newly introduced columns to existing SQLite tables if not present."""
    import sqlite3
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("PRAGMA table_info(projects)")
        proj_cols = [row[1] for row in cur.fetchall()]
        if "delay_ms" not in proj_cols:
            cur.execute("ALTER TABLE projects ADD COLUMN delay_ms INTEGER DEFAULT 0")
        if "upstream_proxy" not in proj_cols:
            cur.execute("ALTER TABLE projects ADD COLUMN upstream_proxy VARCHAR(255) DEFAULT ''")

        cur.execute("PRAGMA table_info(http_logs)")
        log_cols = [row[1] for row in cur.fetchall()]
        if "agent_id" not in log_cols:
            cur.execute("ALTER TABLE http_logs ADD COLUMN agent_id VARCHAR(100) DEFAULT 'primary_agent'")
        con.commit()
        con.close()
    except Exception as ex:
        pass


def init_db():
    """Create all database tables, perform schema migrations, and ensure default project exists."""
    Base.metadata.create_all(bind=engine)
    
    # Run column migrations for SQLite
    _run_migrations()

    db = SessionLocal()
    try:
        default_proj = db.query(Project).filter(Project.name == "default").first()
        if not default_proj:
            db.add(Project(
                name="default",
                description="Default security testing workspace",
                scope_enabled=False,
                allowed_hosts=json.dumps(["*"]),
                blocked_patterns=json.dumps(["logout", "delete.*user", "payment", "checkout"]),
                delay_ms=0,
                upstream_proxy=""
            ))
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def get_db() -> Generator[Session, None, None]:
    """Dependency for obtaining a SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

