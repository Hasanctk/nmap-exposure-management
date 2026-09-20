def compute_scan_diff(previous_scan: dict, current_scan: dict) -> dict:
    """İki tarama sonucu arasındaki port, servis ve zafiyet farklarını hesaplar."""
    def flatten_ports(scan_data: dict) -> dict[tuple[str, str], dict]:
        flattened = {}
        hosts = scan_data.get("hosts", []) if isinstance(scan_data, dict) else []
        for host in hosts:
            ip = None
            for addr in host.get("addresses", []):
                if addr.get("type") in ("ipv4", "ipv6") or not ip:
                    ip = addr.get("addr")
                    if addr.get("type") == "ipv4":
                        break
            if not ip:
                ip = scan_data.get("target", "unknown")

            for p in host.get("ports", []):
                port_id = str(p.get("portid", ""))
                if port_id:
                    flattened[(ip, port_id)] = p
        return flattened

    prev_ports = flatten_ports(previous_scan)
    curr_ports = flatten_ports(current_scan)

    prev_keys = set(prev_ports.keys())
    curr_keys = set(curr_ports.keys())

    # 1. Yeni Açılan Portlar
    added_ports = [
        {"ip": ip, **curr_ports[(ip, port)]}
        for ip, port in (curr_keys - prev_keys)
    ]

    # 2. Kapanan Portlar
    removed_ports = [
        {"ip": ip, **prev_ports[(ip, port)]}
        for ip, port in (prev_keys - curr_keys)
    ]

    # 3. Değişen Servis / Versiyonlar
    modified_ports = []
    for key in (prev_keys & curr_keys):
        p_old = prev_ports[key]
        p_new = curr_ports[key]

        old_ver = f"{p_old.get('product', '')} {p_old.get('version', '')}".strip()
        new_ver = f"{p_new.get('product', '')} {p_new.get('version', '')}".strip()

        if old_ver != new_ver or p_old.get("state") != p_new.get("state"):
            modified_ports.append({
                "ip": key[0],
                "portid": key[1],
                "old": {"service": p_old.get("service"), "version": old_ver, "state": p_old.get("state")},
                "new": {"service": p_new.get("service"), "version": new_ver, "state": p_new.get("state")}
            })

    return {
        "target": current_scan.get("target", "unknown"),
        "previous_task_id": previous_scan.get("task_id"),
        "current_task_id": current_scan.get("task_id"),
        "summary": {
            "new_ports_count": len(added_ports),
            "closed_ports_count": len(removed_ports),
            "modified_ports_count": len(modified_ports)
        },
        "changes": {
            "new_open_ports": added_ports,
            "closed_ports": removed_ports,
            "modified_services": modified_ports
        }
    }