import defusedxml.ElementTree as ET
from app.vuln_matcher import correlate_vulnerabilities

def extract_live_hosts_and_ports(xml_string: str) -> dict:
    """
    1. aşama çıktısından açık portları ve paket kaybı şüphesi
    olan portları (filtered) ayrıştırır.
    """
    results = {"open": {}, "suspicious": {}}
    if not xml_string:
        return results

    try:
        root = ET.fromstring(xml_string)
    except Exception:
        return results

    for host in root.findall("host"):
        addr_elem = host.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr")
        if not ip:
            continue

        open_ports = []
        suspicious_ports = []

        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state_elem = port.find("state")
                if state_elem is None:
                    continue
                state = state_elem.get("state")
                port_id = port.get("portid")

                if state == "open" and port_id:
                    open_ports.append(port_id)
                elif state in ("filtered", "open|filtered") and port_id:
                    suspicious_ports.append(port_id)

        if open_ports:
            results["open"][ip] = open_ports
        if suspicious_ports:
            results["suspicious"][ip] = suspicious_ports

    return results

def parse_full_nmap_xml(xml_string: str) -> dict:
    """Nmap detaylı XML çıktısını parse eder ve CVE eşleştirmelerini ekler."""
    parsed_data = {"hosts": []}
    if not xml_string:
        return parsed_data

    try:
        root = ET.fromstring(xml_string)
    except Exception:
        return parsed_data

    for host in root.findall("host"):
        host_info = {"addresses": [], "ports": [], "os": []}

        for addr in host.findall("address"):
            host_info["addresses"].append({
                "addr": addr.get("addr"),
                "type": addr.get("addrtype")
            })

        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state_elem = port.find("state")
                service_elem = port.find("service")

                state = state_elem.get("state") if state_elem is not None else "unknown"
                service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.get("product", "") if service_elem is not None else ""
                version = service_elem.get("version", "") if service_elem is not None else ""

                vulnerabilities = correlate_vulnerabilities(product, version)

                host_info["ports"].append({
                    "portid": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": state,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "vulnerabilities": vulnerabilities
                })

        os_elem = host.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                host_info["os"].append({
                    "name": osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy")
                })

        parsed_data["hosts"].append(host_info)

    return parsed_data