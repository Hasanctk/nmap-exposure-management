import json
from app.database import SessionLocal
from app.models import ScanRecord, HostRecord, PortRecord

def save_scan_to_postgres(task_id: str, scan_data: dict):
    """Celery worker taramayı bitirdiğinde sonucu kalıcı olarak PostgreSQL'e yazar."""
    db = SessionLocal()
    try:
        # Daha önce bu task_id ile kayıt yapıldı mı kontrol et
        existing = db.query(ScanRecord).filter(ScanRecord.task_id == task_id).first()
        if existing:
            return

        scan_record = ScanRecord(
            task_id=task_id,
            target=scan_data.get("target"),
            profile=scan_data.get("profile"),
            status=scan_data.get("status"),
            open_ports_count=scan_data.get("open_ports_count", 0)
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)

        # Host ve Portları işle
        for h in scan_data.get("hosts", []):
            addresses = h.get("addresses", [])
            ip = addresses[0].get("addr") if addresses else "unknown"
            
            os_list = h.get("os", [])
            os_name = os_list[0].get("name") if os_list else None

            host_record = HostRecord(
                scan_id=scan_record.id,
                ip_address=ip,
                os_info=os_name
            )
            db.add(host_record)
            db.commit()
            db.refresh(host_record)

            for p in h.get("ports", []):
                vulns = p.get("vulnerabilities", [])
                port_record = PortRecord(
                    host_id=host_record.id,
                    portid=int(p.get("portid", 0)),
                    protocol=p.get("protocol", "tcp"),
                    state=p.get("state", "open"),
                    service=p.get("service", "unknown"),
                    product=p.get("product"),
                    version=p.get("version"),
                    vulnerabilities=json.dumps(vulns)
                )
                db.add(port_record)
            
            db.commit()
    except Exception as e:
        db.rollback()
        print(f"PostgreSQL kayıt hatası: {e}")
    finally:
        db.close()