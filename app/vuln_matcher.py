import json
import logging
import httpx
import redis

logger = logging.getLogger(__name__)

REDIS_URL = "redis://redis:6379/0"
try:
    redis_client = redis.Redis.from_url(REDIS_URL)
except Exception:
    redis_client = None

CVE_CACHE_TTL = 86400  # 24 saat önbellek

FALLBACK_CVE_DB = [
    {
        "keywords": ["dropbear", "2020.80"],
        "cve_id": "CVE-2021-36369",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Dropbear SSH sunucusunda kullanıcı doğrulama bilgi sızıntısı."
    },
    {
        "keywords": ["dnsmasq", "2.85"],
        "cve_id": "CVE-2023-28450",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Dnsmasq DNS yanıt boyutu manipülasyonu ile DoS riski."
    },
    {
        "keywords": ["samba", "3."],
        "cve_id": "CVE-2017-7494",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "SambaCry: Uzaktan rastgele kod çalıştırma (RCE) zafiyeti."
    }
]

def _fetch_from_api(product: str, version: str) -> list[dict]:
    """Açık CIRCL CVE-Search API üzerinden zafiyet sorgular."""
    query = f"{product} {version}".strip()
    url = f"https://cve.circl.lu/api/search/{query}"

    try:
        with httpx.Client(timeout=4.0) as client:
            response = client.get(url)
            if response.status_code != 200:
                return []
            
            data = response.json()
            results = data.get("data", data) if isinstance(data, dict) else data
            if not isinstance(results, list):
                return []

            matched_cves = []
            for item in results[:3]:
                cve_id = item.get("id") or item.get("cve", "Bilinmeyen CVE")
                cvss = float(item.get("cvss") or 5.0)
                summary = item.get("summary", "Açıklama bulunamadı.")
                
                if cvss >= 9.0:
                    severity = "CRITICAL"
                elif cvss >= 7.0:
                    severity = "HIGH"
                elif cvss >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                matched_cves.append({
                    "cve_id": cve_id,
                    "severity": severity,
                    "cvss": cvss,
                    "description": summary[:140] + "..." if len(summary) > 140 else summary
                })
            return matched_cves
    except Exception as e:
        logger.warning(f"CVE API sorgusunda hata ({query}): {e}")
        return []

def correlate_vulnerabilities(product: str, version: str) -> list[dict]:
    if not product:
        return []

    cache_key = f"cve:cache:{product.lower().strip()}:{version.lower().strip()}"

    # 1. Aşama: Redis Önbellek
    if redis_client:
        try:
            cached = redis_client.get(cache_key)
            if cached:
                return json.loads(cached.decode("utf-8"))
        except Exception:
            pass

    # 2. Aşama: Canlı API
    matches = _fetch_from_api(product, version)

    # 3. Aşama: Fallback
    if not matches:
        search_text = f"{product} {version}".lower()
        for entry in FALLBACK_CVE_DB:
            if all(kw.lower() in search_text for kw in entry["keywords"]):
                matches.append({
                    "cve_id": entry["cve_id"],
                    "severity": entry["severity"],
                    "cvss": entry["cvss"],
                    "description": entry["description"]
                })

    if redis_client and matches:
        try:
            redis_client.setex(cache_key, CVE_CACHE_TTL, json.dumps(matches))
        except Exception:
            pass

    return matches