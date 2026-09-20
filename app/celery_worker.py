import ipaddress
import json
import redis
from celery import Celery, group
from celery.schedules import crontab
from celery.exceptions import SoftTimeLimitExceeded

from app.scanner import SCAN_PROFILES, run_nmap_stage
from app.parser import extract_live_hosts_and_ports, parse_full_nmap_xml
from app.diff_engine import compute_scan_diff
from app.notifier import trigger_audit_alert_if_needed
from app.database_ops import save_scan_to_postgres
from app.nuclei_runner import run_nuclei_scan

REDIS_URL = "redis://redis:6379/0"

celery_app = Celery("nmap_worker", broker=REDIS_URL, backend=REDIS_URL)
redis_client = redis.Redis.from_url(REDIS_URL)

CACHE_TTL = 3600

# --- CELERY BEAT (ZAMANLAYICI) AYARLARI ---
celery_app.conf.beat_schedule = {
    'nightly-security-audit': {
        'task': 'app.celery_worker.run_nmap_scan',
        'schedule': crontab(hour=3, minute=0),
        'args': ('192.168.0.0/24', 'fast', True), 
    },
}
# ------------------------------------------

def split_cidr_target(target: str, max_prefix: int = 24) -> list[str]:
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.prefixlen < max_prefix:
            return [str(subnet) for subnet in network.subnets(new_prefix=max_prefix)]
        return [target]
    except ValueError:
        return [target]

def _process_autonomous_audit(target: str, current_scan_data: dict):
    history_key = f"audit:history:{target}"
    last_scan_raw = redis_client.get(history_key)

    if last_scan_raw:
        last_scan_data = json.loads(last_scan_raw.decode("utf-8"))
        diff_result = compute_scan_diff(last_scan_data, current_scan_data)
        trigger_audit_alert_if_needed(diff_result)

    redis_client.set(history_key, json.dumps(current_scan_data))

@celery_app.task(bind=True, soft_time_limit=300, time_limit=360)
def scan_chunk_task(self, chunk_target: str, profile: str = "fast"):
    config = SCAN_PROFILES.get(profile, SCAN_PROFILES["fast"])
    try:
        discovery_xml = run_nmap_stage(config["discovery"], target=chunk_target)
        extracted = extract_live_hosts_and_ports(discovery_xml)
        live_hosts_map = extracted.get("open", {})

        if not live_hosts_map:
            return {"hosts": [], "open_ports_count": 0}

        all_unique_ports = sorted(list({p for ports in live_hosts_map.values() for p in ports}))
        live_ips = list(live_hosts_map.keys())

        port_arg = ["-p", ",".join(all_unique_ports)]
        service_args = config["service"] + port_arg + live_ips
        service_xml = run_nmap_stage(service_args, target=None)

        parsed = parse_full_nmap_xml(service_xml)
        
        # Chunk seviyesinde de aktif Nuclei zafiyet taraması entegrasyonu
        for host in parsed.get("hosts", []):
            addresses = host.get("addresses", [])
            if not addresses:
                continue
            ip = addresses[0].get("addr")
            for p in host.get("ports", []):
                if p.get("state") == "open":
                    portid = int(p.get("portid", 0))
                    p["vulnerabilities"] = run_nuclei_scan(ip, portid)

        return {
            "hosts": parsed.get("hosts", []),
            "open_ports_count": sum(len(p) for p in live_hosts_map.values())
        }
    except Exception:
        return {"hosts": [], "open_ports_count": 0}

@celery_app.task(bind=True, soft_time_limit=1800, time_limit=1900)
def run_nmap_scan(self, target: str, profile: str = "balanced", audit_mode: bool = False):
    cache_key = f"cache:scan:{target}:{profile}"
    cached_data = redis_client.get(cache_key)

    if cached_data and not audit_mode:
        res = json.loads(cached_data.decode("utf-8"))
        res["cached"] = True
        return res

    chunks = split_cidr_target(target, max_prefix=24)

    if len(chunks) > 1:
        self.update_state(
            state="PROGRESS",
            meta={
                "stage": "Parallel Chunking",
                "detail": f"{target} bloğu {len(chunks)} adet /24 parçasına bölündü..."
            }
        )

        job_group = group(scan_chunk_task.s(chunk, profile) for chunk in chunks)
        group_async = job_group.apply_async()
        results = group_async.get()

        aggregated_hosts = []
        total_open_ports = 0

        for r in results:
            if isinstance(r, dict):
                aggregated_hosts.extend(r.get("hosts", []))
                total_open_ports += r.get("open_ports_count", 0)

        final_result = {
            "target": target,
            "profile": profile,
            "status": "completed",
            "message": f"{len(chunks)} alt blok paralel tarandı.",
            "hosts": aggregated_hosts,
            "open_ports_count": total_open_ports,
            "partial": False,
            "cached": False
        }
        redis_client.setex(cache_key, CACHE_TTL, json.dumps(final_result))
        
        save_scan_to_postgres(self.request.id or "autonomous_scan", final_result)
        
        if audit_mode:
            _process_autonomous_audit(target, final_result)
            
        return final_result

    config = SCAN_PROFILES.get(profile, SCAN_PROFILES["balanced"])
    live_hosts_map = {}

    try:
        self.update_state(state="PROGRESS", meta={"stage": "1/2", "detail": "Ağ keşfi yapılıyor..."})
        discovery_xml = run_nmap_stage(config["discovery"], target=target)
        extracted = extract_live_hosts_and_ports(discovery_xml)
        live_hosts_map = extracted.get("open", {})

        if not live_hosts_map:
            final_result = {
                "target": target,
                "profile": profile,
                "status": "completed",
                "message": "Açık port tespit edilemedi veya hedef kapalı.",
                "hosts": [],
                "open_ports_count": 0,
                "partial": False,
                "cached": False
            }
            redis_client.setex(cache_key, CACHE_TTL, json.dumps(final_result))
            
            save_scan_to_postgres(self.request.id or "autonomous_scan", final_result)
            
            if audit_mode:
                _process_autonomous_audit(target, final_result)
                
            return final_result

        all_unique_ports = sorted(list({p for ports in live_hosts_map.values() for p in ports}))
        live_ips = list(live_hosts_map.keys())

        self.update_state(state="PROGRESS", meta={"stage": "2/2", "detail": "Açık portlar doğrulanıyor..."})

        port_arg = ["-p", ",".join(all_unique_ports)]
        service_args = config["service"] + port_arg + live_ips
        service_xml = run_nmap_stage(service_args, target=None)

        parsed_result = parse_full_nmap_xml(service_xml)
        
        # --- NUCLEI AKTİF ZAFİYET DOĞRULAMA ENTEGRASYONU ---
        for host in parsed_result.get("hosts", []):
            addresses = host.get("addresses", [])
            if not addresses:
                continue
            ip = addresses[0].get("addr")
            for p in host.get("ports", []):
                if p.get("state") == "open":
                    portid = int(p.get("portid", 0))
                    p["vulnerabilities"] = run_nuclei_scan(ip, portid)
        # ----------------------------------------------------

        parsed_result["target"] = target
        parsed_result["profile"] = profile
        parsed_result["open_ports_count"] = sum(len(ports) for ports in live_hosts_map.values())
        parsed_result["partial"] = False
        parsed_result["cached"] = False

        redis_client.setex(cache_key, CACHE_TTL, json.dumps(parsed_result))
        
        save_scan_to_postgres(self.request.id or "autonomous_scan", parsed_result)
        
        if audit_mode:
            _process_autonomous_audit(target, parsed_result)
            
        return parsed_result

    except SoftTimeLimitExceeded:
        partial_hosts = []
        for ip, ports in live_hosts_map.items():
            ports_payload = [
                {"portid": p, "protocol": "tcp", "state": "open", "service": "unresolved", "product": "", "version": "", "vulnerabilities": []}
                for p in ports
            ]
            partial_hosts.append({"addresses": [{"addr": ip, "type": "ipv4"}], "ports": ports_payload, "os": []})

        timeout_result = {
            "target": target,
            "profile": profile,
            "status": "partial_timeout",
            "message": "Tarama zaman aşımına uğradı.",
            "hosts": partial_hosts,
            "open_ports_count": sum(len(ports) for ports in live_hosts_map.values()),
            "partial": True,
            "cached": False
        }
        
        save_scan_to_postgres(self.request.id or "autonomous_scan", timeout_result)
        
        if audit_mode:
            _process_autonomous_audit(target, timeout_result)
            
        return timeout_result