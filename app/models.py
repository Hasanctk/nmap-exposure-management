from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base

class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String, unique=True, index=True)
    target = Column(String, index=True)
    profile = Column(String)
    status = Column(String)
    open_ports_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    hosts = relationship("HostRecord", back_populates="scan", cascade="all, delete-orphan")


class HostRecord(Base):
    __tablename__ = "host_records"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_records.id"))
    ip_address = Column(String, index=True)
    os_info = Column(String, nullable=True)

    scan = relationship("ScanRecord", back_populates="hosts")
    ports = relationship("PortRecord", back_populates="host", cascade="all, delete-orphan")


class PortRecord(Base):
    __tablename__ = "port_records"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("host_records.id"))
    portid = Column(Integer)
    protocol = Column(String)
    state = Column(String)
    service = Column(String)
    product = Column(String, nullable=True)
    version = Column(String, nullable=True)
    vulnerabilities = Column(Text, nullable=True) # JSON string olarak saklanacak

    host = relationship("HostRecord", back_populates="ports")