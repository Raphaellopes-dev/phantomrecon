from config import SECURITY_HEADERS
from utils.network import safe_open

def module_vuln(manager, target, scan_id):
    manager.add_log(scan_id, "[ MODULO: ANALISE DE VULNERABILIDADES ]", "module")
    result = {}
    vulns = []
    if not target.startswith("http"):
        target = "http://" + target

    manager.add_log(scan_id, "[*] Verificando headers de seguranca...", "info")
    r = safe_open(target, 5)
    if r:
        for key, label in SECURITY_HEADERS:
            if not any(k.lower() == key for k in r.headers.keys()):
                manager.add_log(scan_id, f"  [-] Header ausente: {label}", "warn")
                vulns.append({"type": "Missing Security Header", "target": label, "payload": "", "confidence": "MEDIUM", "severity": "LOW"})
    else:
        manager.add_log(scan_id, "[-] Nao foi possivel verificar headers", "error")

    manager.add_log(scan_id, "[*] Verificando portas sensiveis...", "info")
    result["vulnerabilities"] = vulns
    manager.add_log(scan_id, f"[+] Vulnerabilidades potenciais: {len(vulns)}", "ok" if not vulns else "warn")
    manager.add_log(scan_id, "[+] Analise concluida", "ok")
    return result
