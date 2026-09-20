import shutil
import subprocess

SCAN_PROFILES = {
    "fast": {
        "discovery": [
            "-sS", "-T4", "-F", "--open", "-n",
            "-PS80,443,22",
            "--max-retries", "2",
            "--initial-rtt-timeout", "200ms",
            "--max-rtt-timeout", "800ms",
            "--min-rate", "600"
        ],
        "service": ["-sS", "-T4", "-sV", "--version-light", "-n"]
    },
    "balanced": {
        "discovery": [
            "-sS", "-T4", "--top-ports", "1000", "-n",
            "-PS80,443,22,8080",
            "--max-retries", "3",
            "--initial-rtt-timeout", "250ms",
            "--max-rtt-timeout", "1000ms",
            "--min-rate", "400"
        ],
        "service": ["-sS", "-T4", "-sV", "-O", "-n"]
    },
    "deep": {
        "discovery": [
            "-sS", "-T4", "-p-", "-n",
            "-PS80,443,22,445,3389",
            "--max-retries", "3",
            "--initial-rtt-timeout", "300ms",
            "--max-rtt-timeout", "1500ms",
            "--min-rate", "500"
        ],
        # Optimize Edilmiş -A Konfigürasyonu (OS + Script + Version + No Traceroute)
        "service": [
            "-sS", "-T4", "-n",
            "-sV", "--version-intensity", "5",
            "-O", "--osscan-limit", "--max-os-tries", "1",
            "-sC", "--script-timeout", "10s"
        ]
    }
}

def run_nmap_stage(args: list[str], target: str | None = None) -> str:
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise RuntimeError("Sistemde nmap komutu bulunamadı.")

    cmd = [nmap_path, "-oX", "-"] + args
    if target:
        cmd.append(target)

    process = subprocess.run(cmd, capture_output=True, text=True)
    if process.returncode != 0:
        raise RuntimeError(f"Nmap yürütme hatası: {process.stderr}")

    return process.stdout