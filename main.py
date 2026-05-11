#!/usr/bin/env python3
"""
PhantomRecon v3.0 — Professional pentest recon toolkit for Windows
by Raphael Lopes — github.com/Raphaellopes-dev
"""

import sys, time, socket, subprocess, json, os, re, webbrowser, threading
from datetime import datetime, UTC
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

VERSION = "3.0.0"
OUTPUT_DIR = "reports"

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5800: "VNC", 5900: "VNC", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 27017: "MongoDB", 50070: "Hadoop"
}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "Clickjacking",
    "x-xss-protection": "XSS",
    "x-content-type-options": "MIME-sniff",
    "referrer-policy": "Referrer",
    "permissions-policy": "Permissions"
}

SENSITIVE_PORTS = [3389, 445, 5985, 5986, 1433, 3306, 6379, 27017]

# ---------------------------------------------------------------------------
# SCAN ENGINE
# ---------------------------------------------------------------------------

def os_from_ttl(ttl):
    if ttl <= 64: return "Linux/Unix"
    if ttl <= 128: return "Windows"
    if ttl <= 255: return "Cisco/Network"
    return "Desconhecido"

def resolve_dns(target):
    try:
        result = socket.gethostbyname_ex(target)
        return {"host": result[0], "aliases": result[1], "ips": result[2]}
    except:
        return None

def ping_host(ip):
    try:
        r = subprocess.run(["ping", "-n", "2", ip], capture_output=True, text=True, timeout=8, creationflags=subprocess.CREATE_NO_WINDOW)
        if r.returncode != 0: return {"alive": False}
        ttl_m = re.search(r"TTL=(\d+)", r.stdout, re.IGNORECASE)
        time_m = re.search(r"(tempo|time)[=<]\s*(\d+)ms", r.stdout, re.IGNORECASE)
        ttl_v = int(ttl_m.group(1)) if ttl_m else None
        return {"alive": True, "latency": time_m.group(2) if time_m else None, "ttl": ttl_v, "os": os_from_ttl(ttl_v) if ttl_m else None}
    except:
        return {"alive": False, "error": "Ping falhou"}

def scan_ports(target, profile="quick"):
    if profile == "quick":
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 27017]
    elif profile == "full":
        ports = list(range(1, 1025)) + [1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986,
                                         6379, 8080, 8443, 9100, 10000, 11211, 27017, 50070]
    else:
        ports = list(COMMON_PORTS.keys())

    banner_ports = {21, 22, 25, 80, 110, 143, 443, 8080, 8443}
    open_ports = []

    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            r = s.connect_ex((target, port))
            if r == 0:
                service = COMMON_PORTS.get(port, "Desconhecido")
                banner = None
                if port in banner_ports:
                    try:
                        bs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        bs.settimeout(2)
                        bs.connect((target, port))
                        if port in (80, 8080):
                            bs.send(f"GET / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: PR/3.0\r\n\r\n".encode())
                        time.sleep(0.3)
                        raw = bs.recv(256).decode("utf-8", errors="ignore").strip()[:80]
                        if "\n" in raw: raw = raw.split("\n")[0].strip()
                        if raw: banner = raw
                        bs.close()
                    except: pass
                s.close()
                return (port, service, banner)
            s.close()
        except: pass
        return None

    with ThreadPoolExecutor(max_workers=50) as ex:
        for f in as_completed({ex.submit(check, p): p for p in ports}):
            r = f.result()
            if r: open_ports.append(r)
    open_ports.sort(key=lambda x: x[0])
    return open_ports

def check_http(target, port=80):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        s.send(f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: PhantomRecon/3.0\r\nConnection: close\r\n\r\n".encode())
        response = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()
        headers_raw = response.split("\r\n\r\n")[0] if "\r\n\r\n" in response else response
        header_lines = headers_raw.split("\r\n")
        status = header_lines[0] if header_lines else ""
        found = {}
        for line in header_lines[1:]:
            for key, label in SECURITY_HEADERS.items():
                if line.lower().startswith(key):
                    val = line.split(":", 1)[1].strip() if ":" in line else ""
                    found[label] = val
        missing = [l for k, l in SECURITY_HEADERS.items() if k not in {k2:v2 for k2,v2 in zip(SECURITY_HEADERS.keys(), SECURITY_HEADERS.values())}]
        missing = [l for k, l in SECURITY_HEADERS.items() if l not in found]
        return {"status": status, "headers": found, "missing": missing, "raw": response[:2000]}
    except:
        return None

def check_https(target, port=443):
    import ssl as sslmod
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        ctx = sslmod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = sslmod.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=target)
        ss.connect((target, port))
        info = {"ssl": True}
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert_der = ss.getpeercert(binary_form=True)
            cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
            exp = cert_obj.not_valid_after
            if exp.tzinfo is not None: exp = exp.replace(tzinfo=None)
            info["subject"] = cert_obj.subject.rfc4514_string()
            info["issuer"] = cert_obj.issuer.rfc4514_string()
            info["expires"] = exp.strftime("%Y-%m-%d %H:%M:%S")
            info["valid"] = exp > datetime.now(UTC).replace(tzinfo=None)
        except ImportError:
            cert = ss.getpeercert()
            info["status"] = "presente" if cert else "ausente"
        ss.close()
        return info
    except:
        try: s.close()
        except: pass
        return None

def enumerate_dns(target):
    found = []
    for rtype in ["A", "MX", "NS", "TXT", "AAAA", "CNAME"]:
        try:
            r = subprocess.run(["nslookup", f"-type={rtype}", target], capture_output=True, text=True, timeout=8, creationflags=subprocess.CREATE_NO_WINDOW)
            for line in r.stdout.split("\n"):
                line = line.strip()
                if ":" in line and target.lower() in line.lower():
                    val = line.split(":", 1)[1].strip()
                    if val and val != target:
                        found.append({"type": rtype, "value": val})
        except: pass
    return found

def generate_html_report(target, result):
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    ips = ", ".join(result.get("ips", []))
    ports = result.get("ports", [])

    status_label = "Exposicao Sensivel" if any(p in SENSITIVE_PORTS for p, _, _ in ports) else "Aberta"
    port_rows = ""
    for port, service, banner in ports:
        cls = "critical" if port in SENSITIVE_PORTS else ""
        vers = f"<br><span style='color:#888;font-size:11px'>{banner[:60]}</span>" if banner else ""
        port_rows += f"<tr><td>{port}</td><td>{service}{vers}</td><td class='{cls}'>{status_label}</td></tr>"

    http_sec = ""
    if result.get("http"):
        h = result["http"]
        sec = "".join(f'<div class="tag">{h}</div>' for h in h.get("headers", {}))
        missing = "".join(f'<div class="tag missing">{m}</div>' for m in h.get("missing", []))
        http_sec = f"""
        <div class="section"><div class="section-title">Headers HTTP</div><div class="section-content">
        <div class="info-item"><span class="label">Status</span><span>{h.get("status","")}</span></div>
        <div class="info-item"><span class="label">Presentes</span><span>{sec or "Nenhum"}</span></div>
        <div class="info-item"><span class="label">Faltando</span><span>{missing or "Nenhum"}</span></div>
        </div></div>"""

    ssl_sec = ""
    if result.get("ssl"):
        s = result["ssl"]
        items = []
        for k, v in s.items():
            if k == "valid":
                items.append(f'<div class="info-item"><span class="label">Valido</span><span class="{"valid" if v else "invalid"}">{"Sim" if v else "Nao"}</span></div>')
            elif k != "ssl":
                items.append(f'<div class="info-item"><span class="label">{k.title()}</span><span>{v}</span></div>')
        ssl_sec = f'<div class="section"><div class="section-title">SSL/TLS</div><div class="section-content"><div class="info-grid">{"".join(items)}</div></div></div>'

    dns_rows = ""
    for d in result.get("dns", []):
        dns_rows += f'<tr><td>{d["type"]}</td><td>{d["value"]}</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="pt-br">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhantomRecon - {target}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:#0a0a0a; color:#c0c0c0; font-family:'Cascadia Code','Fira Code','Consolas',monospace; padding:20px; }}
.container {{ max-width:900px; margin:0 auto; }}
.header {{ text-align:center; padding:40px 0; border-bottom:1px solid #00ff88; margin-bottom:30px; }}
.header h1 {{ color:#00ff88; font-size:28px; letter-spacing:3px; }}
.header .sub {{ color:#666; font-size:13px; margin-top:5px; }}
.header .target {{ color:#00ff88; font-size:18px; margin-top:10px; }}
.header .date {{ color:#555; font-size:12px; margin-top:5px; }}
.section {{ background:#111; border:1px solid #222; border-radius:6px; margin-bottom:20px; overflow:hidden; }}
.section-title {{ background:#1a1a1a; padding:12px 18px; color:#00ff88; font-weight:bold; font-size:14px; border-bottom:1px solid #222; }}
.section-content {{ padding:15px 18px; font-size:13px; line-height:1.6; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th {{ text-align:left; padding:10px 12px; background:#1a1a1a; color:#00ff88; border-bottom:1px solid #333; }}
td {{ padding:8px 12px; border-bottom:1px solid #1a1a1a; }}
td.critical {{ color:#ff4444; font-weight:bold; }}
.info-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }}
.info-item {{ background:#0d0d0d; padding:10px 14px; border-radius:4px; border-left:3px solid #00ff88; margin-bottom:8px; }}
.info-item .label {{ display:block; font-size:10px; color:#666; text-transform:uppercase; letter-spacing:1px; margin-bottom:4px; }}
.tag {{ display:inline-block; background:#1a3a2a; color:#00ff88; padding:2px 8px; border-radius:3px; font-size:11px; margin:2px; }}
.tag.missing {{ background:#3a1a1a; color:#ff4444; }}
.valid {{ color:#00ff88; }}
.invalid {{ color:#ff4444; }}
.footer {{ text-align:center; padding:30px 0; color:#444; font-size:12px; border-top:1px solid #1a1a1a; margin-top:30px; }}
.footer a {{ color:#00ff88; text-decoration:none; }}
</style></head>
<body><div class="container">
<div class="header"><h1>PHANTOMRECON</h1><div class="sub">Pentest Recon Toolkit for Windows</div><div class="target">{target}</div><div class="date">{now}</div></div>
<div class="section"><div class="section-title">Alvo</div><div class="section-content"><div class="info-grid">
<div class="info-item"><span class="label">Host</span><span>{target}</span></div>
<div class="info-item"><span class="label">IPs</span><span>{ips or "N/A"}</span></div>
<div class="info-item"><span class="label">Portas Abertas</span><span>{len(ports)}</span></div>
<div class="info-item"><span class="label">Operador</span><span>Raphael Lopes</span></div>
</div></div></div>
<div class="section"><div class="section-title">Portas Abertas ({len(ports)})</div><div class="section-content">
<table><tr><th>Porta</th><th>Servico</th><th>Status</th></tr>{port_rows or '<tr><td colspan="3">Nenhuma porta aberta</td></tr>'}</table></div></div>
{http_sec}{ssl_sec}
{"".join(f'<div class="section"><div class="section-title">DNS: {d["type"]}</div><div class="section-content">{d["value"]}</div></div>' for d in result.get("dns", []))}
<div class="footer">Gerado pelo PhantomRecon v{VERSION} &mdash; <a href="https://github.com/Raphaellopes-dev/phantomrecon" target="_blank">github.com/Raphaellopes-dev/phantomrecon</a></div>
</div></body></html>"""
    return html

def generate_txt_report(target, result):
    lines = ["="*60]
    lines.append(f"  PHANTOMRECON v{VERSION} - Relatorio de Reconhecimento")
    lines.append(f"  Alvo: {target}")
    lines.append(f"  Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    lines.append(f"  Operador: Raphael Lopes")
    lines.append("="*60 + "\n")
    if result.get("ips"):
        lines.append(f"  IPs: {', '.join(result['ips'])}")
    if result.get("ports"):
        lines.append("\n  PORTAS ABERTAS:")
        lines.append("-"*40)
        for p, s, b in result["ports"]:
            line = f"    {p}/TCP  {s}"
            if b: line += f"  |  {b[:60]}"
            lines.append(line)
    lines.append("\n" + "="*60)
    lines.append("  github.com/Raphaellopes-dev")
    lines.append("="*60)
    return "\n".join(lines)

def save_reports(target, result):
    Path(OUTPUT_DIR).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    sf = re.sub(r'[^\w.-]', '_', target)
    html = generate_html_report(target, result)
    html_file = f"{OUTPUT_DIR}/recon_{sf}_{ts}.html"
    with open(html_file, "w", encoding="utf-8") as f: f.write(html)
    txt = generate_txt_report(target, result)
    txt_file = f"{OUTPUT_DIR}/recon_{sf}_{ts}.txt"
    with open(txt_file, "w", encoding="utf-8") as f: f.write(txt)
    return txt_file, html_file

def run_recon(target, profile="quick", callback=None):
    result = {"target": target, "profile": profile, "start": datetime.now().isoformat()}

    if callback: callback({"stage": "dns", "msg": "Resolvendo DNS..."})
    dns = resolve_dns(target)
    if dns:
        ips = dns["ips"]
        result["ips"] = ips
        result["dns_data"] = dns
        main_ip = ips[0]
    else:
        result["ips"] = []
        main_ip = target
        if callback: callback({"stage": "dns", "msg": "DNS fallback: usando como IP"})

    if callback: callback({"stage": "ping", "msg": "Testando ping..."})
    ping = ping_host(main_ip)
    result["ping"] = ping

    if callback: callback({"stage": "ports", "msg": f"Escaneando portas ({profile})..."})
    ports = scan_ports(main_ip, profile)
    result["ports"] = ports
    if callback: callback({"stage": "ports_done", "msg": f"{len(ports)} portas abertas encontradas", "count": len(ports)})

    http_data = None
    https_data = None
    for port, service, _ in ports:
        if port in (80, 8080):
            if callback: callback({"stage": "http", "msg": f"Analisando HTTP na porta {port}..."})
            http_data = check_http(target, port)
        if port in (443, 8443):
            if callback: callback({"stage": "ssl", "msg": f"Analisando SSL na porta {port}..."})
            https_data = check_https(target, port)
    if not http_data and not https_data:
        if callback: callback({"stage": "http", "msg": "Testando HTTP na porta 80..."})
        http_data = check_http(target, 80)
    result["http"] = http_data
    result["ssl"] = https_data

    if callback: callback({"stage": "dns_enum", "msg": "Enumerando registros DNS..."})
    result["dns"] = enumerate_dns(target)

    if callback: callback({"stage": "report", "msg": "Gerando relatorios..."})
    txt_file, html_file = save_reports(target, result)
    result["txt_file"] = txt_file
    result["html_file"] = html_file

    if callback: callback({"stage": "done", "msg": "Reconhecimento concluido!", "result": result})
    return result

# ---------------------------------------------------------------------------
# WEB UI
# ---------------------------------------------------------------------------

HTML_PAGE = """<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhantomRecon</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
@keyframes blink { 50% { opacity:0; } }
body { background:#0a0a0a; color:#c0c0c0; font-family:'Consolas','Courier New',monospace; min-height:100vh; }
.container { max-width:800px; margin:0 auto; padding:30px 20px; }
.header { text-align:center; padding:30px 0; border-bottom:1px solid #00ff88; margin-bottom:30px; }
.header h1 { color:#00ff88; font-size:26px; letter-spacing:4px; }
.header .sub { color:#555; font-size:12px; margin-top:4px; }
.input-area { display:flex; gap:10px; margin-bottom:20px; flex-wrap:wrap; }
.input-area input { flex:1; min-width:200px; padding:12px 16px; background:#111; border:1px solid #333; color:#00ff88; font-family:inherit; font-size:14px; border-radius:4px; outline:none; }
.input-area input:focus { border-color:#00ff88; }
.input-area input::placeholder { color:#444; }
.input-area select { padding:12px; background:#111; border:1px solid #333; color:#00ff88; font-family:inherit; font-size:14px; border-radius:4px; outline:none; cursor:pointer; }
.input-area select:focus { border-color:#00ff88; }
.btn { padding:12px 28px; background:#00ff88; color:#0a0a0a; border:none; font-family:inherit; font-size:14px; font-weight:bold; border-radius:4px; cursor:pointer; transition:.2s; }
.btn:hover { background:#00cc6a; }
.btn:disabled { opacity:.4; cursor:not-allowed; }
.status-bar { background:#111; border:1px solid #222; border-radius:4px; padding:12px 16px; margin-bottom:20px; font-size:13px; min-height:48px; display:flex; align-items:center; gap:8px; }
.status-bar .spinner { width:12px; height:12px; border:2px solid #333; border-top-color:#00ff88; border-radius:50%; animation:spin .8s linear infinite; display:none; }
@keyframes spin { to { transform:rotate(360deg); } }
.status-bar.scanning .spinner { display:inline-block; }
.status-text { color:#888; }
.status-text .highlight { color:#00ff88; }
.status-bar.done .status-text { color:#00ff88; }
.section { background:#111; border:1px solid #222; border-radius:6px; margin-bottom:16px; overflow:hidden; display:none; }
.section.visible { display:block; }
.section-title { background:#1a1a1a; padding:10px 16px; color:#00ff88; font-weight:bold; font-size:13px; border-bottom:1px solid #222; }
.section-content { padding:12px 16px; font-size:13px; line-height:1.7; overflow-x:auto; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { text-align:left; padding:8px 10px; background:#1a1a1a; color:#00ff88; border-bottom:1px solid #333; white-space:nowrap; }
td { padding:7px 10px; border-bottom:1px solid #1a1a1a; }
td.critical { color:#ff4444; font-weight:bold; }
.info-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
.info-item { background:#0d0d0d; padding:8px 12px; border-radius:4px; border-left:3px solid #00ff88; }
.info-item .label { display:block; font-size:10px; color:#666; text-transform:uppercase; letter-spacing:1px; margin-bottom:2px; }
.tag { display:inline-block; background:#1a3a2a; color:#00ff88; padding:2px 7px; border-radius:3px; font-size:11px; margin:2px; }
.tag.missing { background:#3a1a1a; color:#ff4444; }
.report-links { text-align:center; padding:20px 0; }
.report-links a { color:#00ff88; text-decoration:none; margin:0 10px; font-size:13px; }
.report-links a:hover { text-decoration:underline; }
.footer { text-align:center; padding:20px 0; color:#444; font-size:11px; border-top:1px solid #1a1a1a; margin-top:20px; }
.footer a { color:#00ff88; text-decoration:none; }
pre { background:#0d0d0d; padding:10px; border-radius:4px; overflow-x:auto; font-size:11px; color:#aaa; max-height:200px; }
</style>
</head>
<body>
<div class="container">
<div class="header"><h1>PHANTOMRECON</h1><div class="sub">Pentest Recon Toolkit for Windows — v3.0.0</div></div>
<div class="input-area">
<input type="text" id="target" placeholder="Dominio ou IP (ex: scanme.nmap.org)" onkeydown="if(event.key==='Enter')startScan()">
<select id="profile"><option value="quick">Quick (26 portas)</option><option value="full">Full (1024+ portas)</option></select>
<button class="btn" id="scanBtn" onclick="startScan()">Escane</button>
</div>
<div class="status-bar" id="statusBar"><div class="spinner"></div><div class="status-text" id="statusText">Pronto para escanear</div></div>
<div id="results"></div>
<div class="footer">PhantomRecon v3.0 — <a href="https://github.com/Raphaellopes-dev/phantomrecon" target="_blank">github.com/Raphaellopes-dev/phantomrecon</a></div>
</div>
<script>
const results = document.getElementById('results');
const statusBar = document.getElementById('statusBar');
const statusText = document.getElementById('statusText');
const scanBtn = document.getElementById('scanBtn');

async function startScan() {
    const target = document.getElementById('target').value.trim();
    if (!target) { document.getElementById('target').focus(); return; }
    const profile = document.getElementById('profile').value;
    scanBtn.disabled = true;
    scanBtn.textContent = 'Escaneando...';
    statusBar.className = 'status-bar scanning';
    results.innerHTML = '';
    statusText.innerHTML = '<span class="highlight">Iniciando reconhecimento...</span>';

    try {
        const resp = await fetch('/api/scan', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({target, profile})
        });
        const data = await resp.json();
        statusBar.className = 'status-bar' + (data.error ? '' : ' done');
        statusText.innerHTML = data.error ? '<span style="color:#ff4444">Erro: '+data.error+'</span>' : '<span class="highlight">Reconhecimento concluido!</span>';
        if (data.error) { scanBtn.disabled = false; scanBtn.textContent = 'Escane'; return; }
        renderResults(data);
    } catch(e) {
        statusBar.className = 'status-bar';
        statusText.innerHTML = '<span style="color:#ff4444">Erro de conexao</span>';
    }
    scanBtn.disabled = false;
    scanBtn.textContent = 'Escane';
}

function renderResults(data) {
    let html = '';
    if (data.ips && data.ips.length) {
        html += '<div class="section visible"><div class="section-title">Alvo</div><div class="section-content"><div class="info-grid">';
        html += '<div class="info-item"><span class="label">Host</span><span>'+escape(data.target)+'</span></div>';
        html += '<div class="info-item"><span class="label">IPs</span><span>'+data.ips.join(', ')+'</span></div>';
        html += '<div class="info-item"><span class="label">Portas Abertas</span><span>'+(data.ports?data.ports.length:0)+'</span></div>';
        if (data.ping && data.ping.alive) {
            html += '<div class="info-item"><span class="label">SO (TTL)</span><span>'+(data.ping.os||'N/A')+'</span></div>';
        }
        html += '</div></div></div>';
    }
    if (data.ports && data.ports.length) {
        html += '<div class="section visible"><div class="section-title">Portas Abertas ('+data.ports.length+')</div><div class="section-content"><table><tr><th>Porta</th><th>Servico</th><th>Versao</th><th>Status</th></tr>';
        for (const p of data.ports) {
            const critical = p[0]===3389||p[0]===445||p[0]===5985||p[0]===5986||p[0]===1433||p[0]===3306||p[0]===6379||p[0]===27017;
            html += '<tr><td>'+p[0]+'</td><td>'+escape(p[1])+'</td><td>'+(p[2]?escape(p[2].substring(0,60)):'-')+'</td><td class="'+(critical?'critical':'')+'">'+(critical?'Exposicao Sensivel':'Aberta')+'</td></tr>';
        }
        html += '</table></div></div>';
    }
    if (data.http) {
        html += '<div class="section visible"><div class="section-title">Headers HTTP</div><div class="section-content">';
        html += '<div class="info-item"><span class="label">Status</span><span>'+escape(data.http.status||'')+'</span></div>';
        const hdrs = Object.keys(data.http.headers||{});
        if (hdrs.length) html += '<div class="info-item"><span class="label">Seguranca</span><span>'+hdrs.map(h=>'<div class="tag">'+h+'</div>').join('')+'</span></div>';
        const miss = data.http.missing||[];
        if (miss.length) html += '<div class="info-item"><span class="label">Faltando</span><span>'+miss.map(m=>'<div class="tag missing">'+m+'</div>').join('')+'</span></div>';
        html += '</div></div>';
    }
    if (data.ssl) {
        html += '<div class="section visible"><div class="section-title">SSL/TLS</div><div class="section-content"><div class="info-grid">';
        for (const [k,v] of Object.entries(data.ssl)) {
            if (k==='ssl') continue;
            const cls = k==='valid' ? (v?'valid':'invalid') : '';
            html += '<div class="info-item"><span class="label">'+k.charAt(0).toUpperCase()+k.slice(1)+'</span><span class="'+cls+'">'+escape(String(v))+'</span></div>';
        }
        html += '</div></div></div>';
    }
    if (data.dns && data.dns.length) {
        html += '<div class="section visible"><div class="section-title">Registros DNS</div><div class="section-content">';
        for (const d of data.dns) {
            html += '<div class="info-item"><span class="label">'+d.type+'</span><span>'+escape(d.value)+'</span></div>';
        }
        html += '</div></div>';
    }
    if (data.html_file || data.txt_file) {
        html += '<div class="report-links">';
        if (data.html_file) html += '<a href="/report/'+encodeURIComponent(data.html_file)+'" target="_blank">Baixar HTML</a>';
        if (data.txt_file) html += '<a href="/report/'+encodeURIComponent(data.txt_file)+'" target="_blank">Baixar TXT</a>';
        html += '</div>';
    }
    results.innerHTML = html;
}

function escape(s) { if (!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
</script>
</body>
</html>"""

class PhantomHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/report/"):
            fname = self.path[8:]
            try:
                with open(fname, "r", encoding="utf-8") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8" if fname.endswith(".html") else "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            except:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))

    def do_POST(self):
        if self.path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
            target = data.get("target", "")
            profile = data.get("profile", "quick")
            result = run_recon(target, profile)
            resp = json.dumps(result, ensure_ascii=False, default=str)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(resp.encode("utf-8"))

    def log_message(self, format, *args):
        pass

def launch_web_ui():
    port = 5656
    server = HTTPServer(("127.0.0.1", port), PhantomHandler)
    url = f"http://127.0.0.1:{port}"
    print(f"\n  PhantomRecon v{VERSION} — Interface Web")
    print(f"  {'='*50}")
    print(f"  Abrindo: {url}")
    print(f"  Pressione Ctrl+C para parar o servidor")
    print(f"  {'='*50}\n")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Servidor encerrado.\n")
        server.server_close()

# ---------------------------------------------------------------------------
# CLI (fallback)
# ---------------------------------------------------------------------------

def cli_mode(target, profile="quick"):
    print(f"\n  PhantomRecon v{VERSION}")
    print(f"  Alvo: {target} | Perfil: {profile}")
    print(f"  {'='*40}\n")
    result = run_recon(target, profile)
    print(f"\n  Relatorios:")
    print(f"    TXT:  {result.get('txt_file')}")
    print(f"    HTML: {result.get('html_file')}")
    print(f"\n  Reconhecimento concluido!\n")

def main():
    if "--ui" in sys.argv:
        launch_web_ui()
    elif len(sys.argv) > 1 and sys.argv[1] != "--ui":
        target = sys.argv[1]
        profile = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] in ("quick", "full") else "quick"
        cli_mode(target, profile)
    else:
        launch_web_ui()

if __name__ == "__main__":
    main()
