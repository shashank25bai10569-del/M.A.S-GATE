from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import uuid
import os
DATABASE_URL = "postgresql://postgres:knahsahS%401@localhost:5432/mas_gateway"
# Create engine
try:
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)
    Base = declarative_base()
    DB_AVAILABLE = True
    print("✅ Database connection configured")
except Exception as e:
    print(f"⚠️ Database not available: {e}")
    DB_AVAILABLE = False
    SessionLocal = None
    Base = declarative_base()

class UploadedFile(Base):
    __tablename__ = "uploaded_files"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String)
    original_filename = Column(String)
    file_size = Column(Integer)
    mime_type = Column(String)
    risk_score = Column(Float)
    status = Column(String)  # clean, suspicious, malicious, quarantined
    yara_matches = Column(JSON, nullable=True)
    risk_factors = Column(JSON, nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    quarantined_at = Column(DateTime, nullable=True)
    user_ip = Column(String, nullable=True)

# Create tables if database is available
if DB_AVAILABLE:
    try:
        Base.metadata.create_all(engine)
        print("✅ Database tables created/verified")
    except Exception as e:
        print(f"⚠️ Could not create tables: {e}")

def save_scan_result(file_data):
    """Save scan result to database"""
    if not DB_AVAILABLE or not SessionLocal:
        print("⚠️ Database not available - skipping save")
        return None
    
    session = SessionLocal()
    try:
        db_file = UploadedFile(**file_data)
        session.add(db_file)
        session.commit()
        return db_file.id
    except Exception as e:
        print(f"❌ Database error: {e}")
        session.rollback()
        return None
    finally:
        session.close()

def get_recent_scans(limit=10):
    """Get recent scans"""
    if not DB_AVAILABLE or not SessionLocal:
        return []
    
    session = SessionLocal()
    try:
        return session.query(UploadedFile).order_by(
            UploadedFile.uploaded_at.desc()
        ).limit(limit).all()
    except Exception as e:
        print(f"❌ Database error: {e}")
        return []
    finally:
        session.close()