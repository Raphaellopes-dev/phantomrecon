import socket, subprocess, time, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, UTC
from config import COMMON_PORTS, SENSITIVE_PORTS, CVE_DB, SCAN_PORTS, BANNER_PORTS
from utils.network import check_port

def os_from_ttl(ttl):
    if ttl <= 64: return "Linux/Unix"
    if ttl <= 128: return "Windows"
    if ttl <= 255: return "Cisco/Network"
    return "Desconhecido"

def match_cve(service, version):
    results = []
    if service not in CVE_DB:
        return results
    for ver_range, info in CVE_DB[service].items():
        try:
            v_parts = [int(x) for x in re.findall(r"\d+", version)]
            if ver_range.startswith("<"):
                limit = [int(x) for x in re.findall(r"\d+", ver_range)]
                if v_parts < limit:
                    results.append(info)
            elif ver_range.startswith(">="):
                limit = [int(x) for x in re.findall(r"\d+", ver_range)]
                if v_parts >= limit:
                    results.append(info)
            else:
                if version.startswith(ver_range):
                    results.append(info)
        except:
            if ver_range in version:
                results.append(info)
    return results

def module_recon(manager, target, scan_id):
    manager.add_log(scan_id, "[ MODULO: RECONHECIMENTO ]", "module")
    manager.add_log(scan_id, f"[>] Alvo: {target}", "info")
    result = {"target": target}

    manager.add_log(scan_id, "[*] Resolvendo DNS...", "info")
    try:
        dns = socket.gethostbyname_ex(target)
        ips = dns[2]
        result["ips"] = ips
        manager.add_log(scan_id, f"[+] Host: {dns[0]}", "ok")
        manager.add_log(scan_id, f"[+] IPs: {', '.join(ips)}", "ok")
        if dns[1]:
            manager.add_log(scan_id, f"[*] Aliases: {', '.join(dns[1])}", "info")
        main_ip = ips[0]
    except:
        manager.add_log(scan_id, "[-] Falha na resolucao DNS", "error")
        main_ip = target
        result["ips"] = []

    manager.add_log(scan_id, "[*] Executando ping...", "info")
    try:
        r = subprocess.run(["ping", "-n", "2", main_ip], capture_output=True, text=True, timeout=8, creationflags=subprocess.CREATE_NO_WINDOW)
        if r.returncode == 0:
            ttl_m = re.search(r"TTL=(\d+)", r.stdout, re.IGNORECASE)
            time_m = re.search(r"(tempo|time)[=<]\s*(\d+)ms", r.stdout, re.IGNORECASE)
            ttl_v = int(ttl_m.group(1)) if ttl_m else None
            ping_r = {"alive": True, "latency": time_m.group(2) if time_m else None, "ttl": ttl_v, "os": os_from_ttl(ttl_v) if ttl_m else None}
            manager.add_log(scan_id, f"[+] Host ativo | Latencia: {ping_r['latency']}ms | TTL: {ttl_v} ({ping_r['os']})", "ok")
            result["ping"] = ping_r
        else:
            manager.add_log(scan_id, "[-] Host nao respondeu ping", "warn")
            result["ping"] = {"alive": False}
    except:
        manager.add_log(scan_id, "[-] Ping falhou", "error")
        result["ping"] = {"alive": False}

    manager.add_log(scan_id, "[*] Escaneando portas (threads: 50)...", "info")
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        fs = {ex.submit(check_port, main_ip, p, target): p for p in SCAN_PORTS}
        for f in as_completed(fs):
            r = f.result()
            if r:
                open_ports.append(r)
    open_ports.sort(key=lambda x: x[0])
    result["ports"] = open_ports

    if open_ports:
        manager.add_log(scan_id, f"[+] {len(open_ports)} portas abertas:", "ok")
        for p, s, b in open_ports:
            tag = " [!] EXPOSICAO SENSIVEL" if p in SENSITIVE_PORTS else ""
            banner_str = f" | {b}" if b else ""
            level = "critical" if p in SENSITIVE_PORTS else "ok"
            manager.add_log(scan_id, f"    {p}/TCP  {s}{banner_str}{tag}", level)
    else:
        manager.add_log(scan_id, "[-] Nenhuma porta aberta", "warn")

    for p, s, _ in open_ports:
        if p in (80, 8080):
            manager.add_log(scan_id, f"[*] Analisando HTTP na porta {p}...", "info")
            try:
                sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sk.settimeout(5)
                sk.connect((main_ip, p))
                sk.send(f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: PR/5.0\r\nConnection: close\r\n\r\n".encode())
                resp = sk.recv(4096).decode("utf-8", errors="ignore")
                sk.close()
                hdr = resp.split("\r\n\r\n")[0] if "\r\n\r\n" in resp else resp
                lines = hdr.split("\r\n")
                http_result = {"status": lines[0] if lines else "", "headers": {}, "missing": []}
                manager.add_log(scan_id, f"[+] Status HTTP: {http_result['status']}", "ok")
                from config import SECURITY_HEADERS
                for line in lines[1:]:
                    for key, label in SECURITY_HEADERS:
                        if line.lower().startswith(key):
                            val = line.split(":", 1)[1].strip() if ":" in line else ""
                            http_result["headers"][label] = val
                            manager.add_log(scan_id, f"  [*] {label}: {val}", "info")
                for _, label in SECURITY_HEADERS:
                    if label not in http_result["headers"]:
                        http_result["missing"].append(label)
                if http_result["missing"]:
                    manager.add_log(scan_id, f"[-] Headers ausentes: {', '.join(http_result['missing'])}", "warn")
                result["http"] = http_result
            except Exception as e:
                manager.add_log(scan_id, f"[-] Erro HTTP: {str(e)[:50]}", "error")

        if p in (443, 8443):
            manager.add_log(scan_id, f"[*] Analisando SSL na porta {p}...", "info")
            import ssl as sslmod
            sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sk.settimeout(5)
            try:
                ctx = sslmod.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = sslmod.CERT_NONE
                ss = ctx.wrap_socket(sk, server_hostname=target)
                ss.connect((main_ip, p))
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    cert_der = ss.getpeercert(binary_form=True)
                    co = x509.load_der_x509_certificate(cert_der, default_backend())
                    exp = co.not_valid_after_utc
                    ssl_result = {"subject": co.subject.rfc4514_string(), "issuer": co.issuer.rfc4514_string(),
                                  "expires": exp.strftime("%Y-%m-%d %H:%M:%S"), "valid": str(exp > datetime.now(UTC))}
                    manager.add_log(scan_id, f"[+] SSL: {ssl_result['subject']}", "ok")
                    manager.add_log(scan_id, f"[+] Validade: {ssl_result['expires']} {'[OK]' if ssl_result['valid']=='True' else '[EXPIRADO]'}", "ok" if ssl_result['valid']=='True' else "warn")
                    result["ssl"] = ssl_result
                except ImportError:
                    manager.add_log(scan_id, "[*] SSL ativo (cryptography nao instalado)", "info")
                    result["ssl"] = {"ssl": True}
                ss.close()
            except:
                manager.add_log(scan_id, "[-] SSL nao disponivel", "warn")

    manager.add_log(scan_id, "[*] Enumerando registros DNS...", "info")
    dns_records = []
    for rtype in ["A", "MX", "NS", "TXT", "AAAA", "CNAME"]:
        try:
            r = subprocess.run(["nslookup", f"-type={rtype}", target], capture_output=True, text=True, timeout=8, creationflags=subprocess.CREATE_NO_WINDOW)
            for line in r.stdout.split("\n"):
                line = line.strip()
                if ":" in line and target.lower() in line.lower():
                    val = line.split(":", 1)[1].strip()
                    if val and val != target:
                        dns_records.append({"type": rtype, "value": val})
                        manager.add_log(scan_id, f"  {rtype}: {val}", "info")
        except:
            pass
    result["dns"] = dns_records

    manager.add_log(scan_id, "[*] Correlacionando CVEs com versoes detectadas...", "info")
    cve_matches = []
    from config import CVE_DB
    for p, s, b in open_ports:
        banner_lower = (b or "").lower()
        for svc_name in CVE_DB:
            if svc_name.lower() not in s.lower() and svc_name.lower() not in banner_lower:
                continue
            ver_match = None
            if svc_name == "OpenSSH":
                m = re.search(r'openssh[_-]?([\d]+\.[\d]+)', banner_lower)
                if m:
                    ver_match = m.group(1)
            elif svc_name == "Apache":
                m = re.search(r'apache/([\d]+\.[\d]+\.?[\d]*)', banner_lower)
                if m:
                    ver_match = m.group(1)
            else:
                m = re.search(r'([\d]+\.[\d]+\.?[\d]*)', banner_lower)
                if m:
                    ver_match = m.group(1)
            if ver_match:
                cves = match_cve(svc_name, ver_match)
                for cve in cves:
                    cve_matches.append({"port": p, "service": svc_name, "version": ver_match, **cve})
                    manager.add_log(scan_id, f"  [!] {cve['cve']} em {svc_name} {ver_match} (porta {p})", "critical")
    result["cves"] = cve_matches
    if not cve_matches:
        manager.add_log(scan_id, "[-] Nenhum CVE conhecido para as verso es detectadas", "info")

    manager.add_log(scan_id, "[+] Reconhecimento concluido", "ok")
    return result
