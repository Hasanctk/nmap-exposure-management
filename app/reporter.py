from datetime import datetime

def generate_markdown_report(scan_data: dict) -> str:
    target = scan_data.get("target", "Bilinmiyor")
    profile = scan_data.get("profile", "Bilinmiyor")
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    md = [
        f"# Ağ Tarama Raporu: {target}",
        f"- **Tarama Tarihi:** {timestamp}",
        f"- **Profil:** {profile.upper()}",
        f"- **Tespit Edilen Açık Port:** {scan_data.get('open_ports_count', 0)}",
        "",
        "## Keşfedilen Servisler ve Zafiyetler",
        "| Port | Protokol | Durum | Servis | Ürün / Sürüm | CVE / Tehdit |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |"
    ]
    
    hosts = scan_data.get("hosts", [])
    if not hosts:
        md.append("\n*Herhangi bir aktif servis veya host bulunamadı.*")
    else:
        for host in hosts:
            for p in host.get("ports", []):
                prod_ver = f"{p.get('product', '')} {p.get('version', '')}".strip() or "-"
                cves = ", ".join([v.get("cve_id") for v in p.get("vulnerabilities", [])]) or "Zafiyet Yok"
                md.append(f"| {p.get('portid')} | {p.get('protocol')} | {p.get('state')} | {p.get('service')} | {prod_ver} | {cves} |")
                
    return "\n".join(md)

def generate_html_report(scan_data: dict) -> str:
    target = scan_data.get("target", "Bilinmiyor")
    profile = scan_data.get("profile", "Bilinmiyor")
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    rows = ""
    for host in scan_data.get("hosts", []):
        for p in host.get("ports", []):
            prod_ver = f"{p.get('product', '')} {p.get('version', '')}".strip() or "-"
            
            vuln_badges = ""
            for v in p.get("vulnerabilities", []):
                color = "#dc2626" if v["severity"] == "CRITICAL" else "#ea580c" if v["severity"] == "HIGH" else "#ca8a04"
                vuln_badges += f"""<div style="margin-bottom: 4px;">
                    <span style="background:{color}; color:white; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:bold;">
                        {v['cve_id']} ({v['severity']} - {v['cvss']})
                    </span>
                    <div style="font-size:11px; color:#64748b;">{v['description']}</div>
                </div>"""
            
            if not vuln_badges:
                vuln_badges = '<span style="color:#16a34a; font-size:12px;">✔ Bilinen risk yok</span>'

            rows += f"""
            <tr>
                <td><strong>{p.get('portid')}</strong></td>
                <td>{p.get('protocol')}</td>
                <td><span style="color: #16a34a; font-weight: bold;">{p.get('state')}</span></td>
                <td>{p.get('service')}</td>
                <td>{prod_ver}</td>
                <td>{vuln_badges}</td>
            </tr>
            """

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Güvenlik & Zafiyet Raporu - {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; background: #f8fafc; color: #1e293b; }}
        .card {{ background: white; border-radius: 8px; padding: 24px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
        h1 {{ margin-top: 0; color: #0f172a; }}
        .badge {{ display: inline-block; padding: 4px 10px; background: #e0e7ff; color: #3730a3; border-radius: 4px; font-size: 14px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
        th {{ background: #f1f5f9; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Hedef Güvenlik ve Zafiyet Analizi: {target}</h1>
        <p><strong>Zaman:</strong> {timestamp} | <span class="badge">Profil: {profile}</span></p>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Protokol</th>
                    <th>Durum</th>
                    <th>Servis</th>
                    <th>Ürün / Versiyon</th>
                    <th>Zafiyet Eşleşmeleri (CVE / CVSS)</th>
                </tr>
            </thead>
            <tbody>
                {rows if rows else '<tr><td colspan="6">Açık port bulunamadı.</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>"""

def generate_diff_html_report(diff_data: dict) -> str:
    target = diff_data.get("target", "Bilinmiyor")
    summary = diff_data.get("summary", {})
    changes = diff_data.get("changes", {})

    new_ports = changes.get("new_open_ports", [])
    closed_ports = changes.get("closed_ports", [])
    modified = changes.get("modified_services", [])

    # Yeni açılan port satırları
    new_rows = ""
    for p in new_ports:
        prod_ver = f"{p.get('product', '')} {p.get('version', '')}".strip() or "-"
        new_rows += f"""
        <tr>
            <td><span class="badge badge-danger">YENİ PORT</span></td>
            <td><strong>{p.get('ip')}</strong></td>
            <td><strong>{p.get('portid')}</strong> ({p.get('protocol')})</td>
            <td>{p.get('service')}</td>
            <td>{prod_ver}</td>
        </tr>
        """

    # Kapanan port satırları
    closed_rows = ""
    for p in closed_ports:
        prod_ver = f"{p.get('product', '')} {p.get('version', '')}".strip() or "-"
        closed_rows += f"""
        <tr>
            <td><span class="badge badge-success">KAPANDI</span></td>
            <td>{p.get('ip')}</td>
            <td><strong>{p.get('portid')}</strong> ({p.get('protocol')})</td>
            <td>{p.get('service')}</td>
            <td>{prod_ver}</td>
        </tr>
        """

    # Değişen servis satırları
    mod_rows = ""
    for m in modified:
        mod_rows += f"""
        <tr>
            <td><span class="badge badge-warning">DEĞİŞTİ</span></td>
            <td>{m.get('ip')}</td>
            <td><strong>{m.get('portid')}</strong></td>
            <td>Eski: {m['old']['service']} ({m['old']['version'] or '-'})<br>
                Yeni: <strong>{m['new']['service']} ({m['new']['version'] or '-'})</strong></td>
            <td>{m['old']['state']} ➔ <strong>{m['new']['state']}</strong></td>
        </tr>
        """

    has_changes = bool(new_rows or closed_rows or mod_rows)

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Ağ Değişiklik ve Fark Analizi - {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; background: #f8fafc; color: #1e293b; }}
        .card {{ background: white; border-radius: 8px; padding: 28px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); max-width: 1100px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #f1f5f9; padding-bottom: 16px; margin-bottom: 20px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }}
        .stat-box {{ padding: 16px; border-radius: 6px; text-align: center; }}
        .stat-box.danger {{ background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; }}
        .stat-box.success {{ background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; }}
        .stat-box.warning {{ background: #fffbeb; border: 1px solid #fde68a; color: #92400e; }}
        .stat-number {{ font-size: 28px; font-weight: bold; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #e2e8f0; vertical-align: middle; }}
        th {{ background: #f8fafc; font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
        .badge-danger {{ background: #dc2626; color: white; }}
        .badge-success {{ background: #16a34a; color: white; }}
        .badge-warning {{ background: #d97706; color: white; }}
        .meta-text {{ font-size: 12px; color: #64748b; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <div>
                <h1 style="margin: 0; font-size: 22px;">Ağ Değişiklik ve Fark Analizi (Diff)</h1>
                <div class="meta-text">Hedef: <strong>{target}</strong> | Önceki İş: {diff_data.get('previous_task_id')} ➔ Güncel İş: {diff_data.get('current_task_id')}</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-box danger">
                <div>Yeni Açılan Portlar (Risk)</div>
                <div class="stat-number">+{summary.get('new_ports_count', 0)}</div>
            </div>
            <div class="stat-box success">
                <div>Kapanan Portlar</div>
                <div class="stat-number">-{summary.get('closed_ports_count', 0)}</div>
            </div>
            <div class="stat-box warning">
                <div>Değişen Servisler</div>
                <div class="stat-number">{summary.get('modified_services_count', 0)}</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Durum</th>
                    <th>IP Adresi</th>
                    <th>Port / Protokol</th>
                    <th>Servis</th>
                    <th>Ürün / Versiyon Detayı</th>
                </tr>
            </thead>
            <tbody>
                {new_rows}
                {closed_rows}
                {mod_rows}
                {"" if has_changes else '<tr><td colspan="5" style="text-align: center; color: #64748b; padding: 24px;">İki tarama arasında herhangi bir değişiklik tespit edilmedi.</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>"""

def generate_markdown_report(scan_data: dict) -> str:
    target = scan_data.get("target", "Bilinmiyor")
    profile = scan_data.get("profile", "balanced")
    hosts = scan_data.get("hosts", [])

    lines = [
        f"# Güvenlik Tarama Raporu: {target}",
        f"**Profil:** {profile} | **Tespit Edilen Host Sayısı:** {len(hosts)}\n",
        "| Port | Protokol | Durum | Servis | Ürün / Sürüm | Zafiyetler |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |"
    ]

    for host in hosts:
        for p in host.get("ports", []):
            prod = f"{p.get('product', '')} {p.get('version', '')}".strip() or "-"
            vulns = ", ".join([v.get("cve_id", "") for v in p.get("vulnerabilities", [])]) or "Temiz"
            lines.append(f"| {p.get('portid')} | {p.get('protocol')} | {p.get('state')} | {p.get('service')} | {prod} | {vulns} |")

    return "\n".join(lines)

def generate_html_report(scan_data: dict) -> str:
    target = scan_data.get("target", "Bilinmiyor")
    profile = scan_data.get("profile", "balanced")
    hosts = scan_data.get("hosts", [])

    rows = ""
    for host in hosts:
        for p in host.get("ports", []):
            prod = f"{p.get('product', '')} {p.get('version', '')}".strip() or "-"
            vulns_list = p.get("vulnerabilities", [])
            
            if vulns_list:
                vuln_badges = ""
                for v in vulns_list:
                    color = "#dc2626" if v.get("severity") == "CRITICAL" else "#ea580c" if v.get("severity") == "HIGH" else "#d97706"
                    vuln_badges += f"""
                    <div style="margin-bottom: 4px;">
                        <span style="background:{color}; color:white; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:bold;">
                            {v.get('cve_id')} ({v.get('severity')} - {v.get('cvss')})
                        </span>
                        <div style="font-size:11px; color:#64748b;">{v.get('description')}</div>
                    </div>
                    """
            else:
                vuln_badges = '<span style="color:#16a34a; font-size:12px;">✓ Bilinen risk yok</span>'

            rows += f"""
            <tr>
                <td><strong>{p.get('portid')}</strong></td>
                <td>{p.get('protocol')}</td>
                <td><span style="color:#16a34a; font-weight:bold;">{p.get('state')}</span></td>
                <td>{p.get('service')}</td>
                <td>{prod}</td>
                <td>{vuln_badges}</td>
            </tr>
            """

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Güvenlik Analizi: {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; background: #f8fafc; color: #1e293b; }}
        .card {{ background: white; border-radius: 8px; padding: 24px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); max-width: 1200px; margin: 0 auto; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f1f5f9; font-size: 13px; text-transform: uppercase; color: #475569; }}
    </style>
</head>
<body>
    <div class="card">
        <h2 style="margin-top:0;">Hedef Güvenlik ve Zafiyet Analizi: {target}</h2>
        <p style="color:#64748b; font-size:14px;">Profil: <span style="background:#e0e7ff; color:#3730a3; padding:2px 8px; border-radius:4px;">{profile}</span></p>
        <table>
            <thead>
                <tr>
                    <th>Port</th><th>Protokol</th><th>Durum</th><th>Servis</th><th>Ürün / Versiyon</th><th>Zafiyet Eşleşmeleri (CVE / CVSS)</th>
                </tr>
            </thead>
            <tbody>
                {rows if rows else '<tr><td colspan="6">Açık port bulunamadı.</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>"""

def generate_diff_html_report(diff_data: dict) -> str:
    """İki tarama arasındaki delta farkını görselleştiren rapor."""
    target = diff_data.get("target", "Bilinmiyor")
    summary = diff_data.get("summary", {})
    changes = diff_data.get("changes", {})

    new_rows = ""
    for p in changes.get("new_open_ports", []):
        prod = f"{p.get('product', '')} {p.get('version', '')}".strip() or "-"
        new_rows += f"""
        <tr>
            <td><span style="background:#dc2626; color:white; padding:4px 8px; border-radius:4px; font-weight:bold; font-size:11px;">YENİ PORT</span></td>
            <td><strong>{p.get('ip')}</strong></td>
            <td><strong>{p.get('portid')}</strong> ({p.get('protocol')})</td>
            <td>{p.get('service')}</td>
            <td>{prod}</td>
        </tr>
        """

    closed_rows = ""
    for p in changes.get("closed_ports", []):
        prod = f"{p.get('product', '')} {p.get('version', '')}".strip() or "-"
        closed_rows += f"""
        <tr>
            <td><span style="background:#16a34a; color:white; padding:4px 8px; border-radius:4px; font-weight:bold; font-size:11px;">KAPANDI</span></td>
            <td>{p.get('ip')}</td>
            <td><strong>{p.get('portid')}</strong> ({p.get('protocol')})</td>
            <td>{p.get('service')}</td>
            <td>{prod}</td>
        </tr>
        """

    mod_rows = ""
    for m in changes.get("modified_services", []):
        mod_rows += f"""
        <tr>
            <td><span style="background:#d97706; color:white; padding:4px 8px; border-radius:4px; font-weight:bold; font-size:11px;">DEĞİŞTİ</span></td>
            <td>{m.get('ip')}</td>
            <td><strong>{m.get('portid')}</strong></td>
            <td>Eski: {m['old']['service']} ({m['old']['version'] or '-'})<br>
                Yeni: <strong>{m['new']['service']} ({m['new']['version'] or '-'})</strong></td>
            <td>{m['old']['state']} ➔ <strong>{m['new']['state']}</strong></td>
        </tr>
        """

    has_changes = bool(new_rows or closed_rows or mod_rows)

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Ağ Fark Analizi - {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; background: #f8fafc; color: #1e293b; }}
        .card {{ background: white; border-radius: 8px; padding: 28px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); max-width: 1100px; margin: 0 auto; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 20px 0; }}
        .stat-box {{ padding: 16px; border-radius: 6px; text-align: center; }}
        .danger {{ background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; }}
        .success {{ background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; }}
        .warning {{ background: #fffbeb; border: 1px solid #fde68a; color: #92400e; }}
        .stat-number {{ font-size: 26px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #e2e8f0; vertical-align: middle; }}
        th {{ background: #f8fafc; font-size: 13px; text-transform: uppercase; color: #64748b; }}
    </style>
</head>
<body>
    <div class="card">
        <h2 style="margin: 0;">Ağ Değişiklik ve Fark Analizi (Scan Diff)</h2>
        <div style="font-size: 12px; color: #64748b; margin-top: 4px;">Hedef: <strong>{target}</strong> | Önceki: {diff_data.get('previous_task_id')} ➔ Güncel: {diff_data.get('current_task_id')}</div>

        <div class="stats-grid">
            <div class="stat-box danger"><div>Yeni Portlar</div><div class="stat-number">+{summary.get('new_ports_count', 0)}</div></div>
            <div class="stat-box success"><div>Kapanan Portlar</div><div class="stat-number">-{summary.get('closed_ports_count', 0)}</div></div>
            <div class="stat-box warning"><div>Değişen Servisler</div><div class="stat-number">{summary.get('modified_ports_count', 0)}</div></div>
        </div>

        <table>
            <thead>
                <tr><th>Durum</th><th>IP Adresi</th><th>Port</th><th>Servis Değişimi</th><th>Detay</th></tr>
            </thead>
            <tbody>
                {new_rows}
                {closed_rows}
                {mod_rows}
                {"" if has_changes else '<tr><td colspan="5" style="text-align: center; color: #64748b; padding: 20px;">Değişiklik bulunamadı.</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>"""