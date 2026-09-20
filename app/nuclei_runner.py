import subprocess
import json
import os

def run_nuclei_scan(target_ip: str, target_port: int = None) -> list:
    """Belirtilen hedef IP ve opsiyonel porta karşı Nuclei zafiyet taraması çalıştırır."""
    target_url = f"http://{target_ip}"
    if target_port:
        target_url = f"http://{target_ip}:{target_port}"
        # Eğer standart web portu değilse genel TCP/Service modunda da tetiklenebilir
    
    output_file = "/tmp/nuclei_output.json"
    
    # Nuclei komutu: JSON formatında çıktı alacak şekilde yapılandırıyoruz
    cmd = [
        "nuclei",
        "-u", target_url,
        "-json-export", output_file,
        "-silent"
    ]
    
    try:
        # Konteyner içinde komutu çalıştır
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        
        vulnerabilities = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        vulnerabilities.append({
                            "template_id": data.get("template-id"),
                            "name": data.get("info", {}).get("name"),
                            "severity": data.get("info", {}).get("severity"), # critical, high, medium, low
                            "matched": data.get("matched-at")
                        })
            os.remove(output_file)
        return vulnerabilities
    except Exception as e:
        print(f"Nuclei tarama hatası: {e}")
        return []