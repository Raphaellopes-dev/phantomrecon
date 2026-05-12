import os, json, re, threading, time, webbrowser
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path

from config import VERSION, EDITION, OUTPUT_DIR, MODE_MODULES
from utils.helpers import calculate_security_score, generate_avaliacao_explanation

# ---------------------------------------------------------------------------
# ScanManager — thread-safe shared state
# ---------------------------------------------------------------------------

class ScanManager:
    def __init__(self):
        self.logs = {}
        self.results = {}
        self.lock = threading.RLock()
        self._next_id = 0

    def next_id(self):
        with self.lock:
            self._next_id += 1
            return self._next_id

    def add_log(self, scan_id, msg, level="info"):
        with self.lock:
            if scan_id not in self.logs:
                self.logs[scan_id] = []
            self.logs[scan_id].append({"msg": msg, "level": level, "time": time.time()})

    def get_log(self, scan_id):
        with self.lock:
            return self.logs.get(scan_id, [])

    def set_results(self, scan_id, results):
        with self.lock:
            self.results[scan_id] = results

    def get_results(self, scan_id):
        with self.lock:
            return self.results.get(scan_id)

    def is_done(self, scan_id):
        with self.lock:
            return scan_id in self.results

manager = ScanManager()

# ---------------------------------------------------------------------------
# Full Scan Orchestrator
# ---------------------------------------------------------------------------

def clean_target(raw):
    raw = raw.strip().strip("/")
    for prefix in ["http://", "https://"]:
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    raw = raw.split("/")[0].split("?")[0].split("#")[0]
    return raw

def run_full_scan(raw_target, scan_id, profile="aggressive"):
    target = clean_target(raw_target)
    manager.add_log(scan_id, f"[ INICIANDO PHANTOMRECON v{VERSION} Free Edition ]", "module")
    manager.add_log(scan_id, f"[>] Alvo: {target}", "info")
    manager.add_log(scan_id, f"[>] Perfil: {profile.upper()}", "info")
    manager.add_log(scan_id, f"[>] Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", "info")
    manager.add_log(scan_id, "=" * 50, "separator")

    modules_to_run = MODE_MODULES.get(profile, MODE_MODULES["aggressive"])
    all_results = {"target": target}

    if "recon" in modules_to_run:
        from core.recon import module_recon
        recon = module_recon(manager, target, scan_id)
        manager.add_log(scan_id, "=" * 50, "separator")
        all_results = {**all_results, **recon}

    if "web_enum" in modules_to_run:
        from core.web_enum import module_web
        web = module_web(manager, target, scan_id)
        manager.add_log(scan_id, "=" * 50, "separator")
        all_results = {**all_results, **web}

    if "crawl" in modules_to_run:
        from core.web_enum import module_crawl
        crawl = module_crawl(manager, target, scan_id)
        manager.add_log(scan_id, "=" * 50, "separator")
        all_results = {**all_results, **crawl}

    if "fingerprint" in modules_to_run:
        from core.fingerprint import module_fingerprint
        fp = module_fingerprint(manager, target, scan_id)
        manager.add_log(scan_id, "=" * 50, "separator")
        all_results = {**all_results, "fingerprint": fp}

    if "vuln" in modules_to_run:
        from core.vuln import module_vuln
        vuln = module_vuln(manager, target, scan_id)
        all_results = {**all_results, **vuln}

    if "exploit" in modules_to_run:
        from core.exploit import module_exploit
        extra = {
            "cves": all_results.get("cves", []),
            "wp": all_results.get("wordpress", {}),
            "forms": all_results.get("forms", []),
            "admin_panels": all_results.get("admin_panels", []),
        }
        exploit = module_exploit(manager, target, scan_id, extra=extra)
        all_results = {**all_results, **exploit}

    manager.add_log(scan_id, "=" * 50, "separator")
    manager.add_log(scan_id, "[*] Calculando security score...", "info")

    security = calculate_security_score(all_results)
    all_results["security_score"] = security
    manager.add_log(scan_id, f"[+] Security Score: {security['score']}/100 ({security['grade']})", "ok")
    if security["deductions"]:
        for d in security["deductions"]:
            manager.add_log(scan_id, f"    - {d}", "warn")

    manager.add_log(scan_id, "[*] Gerando avaliacao final...", "info")
    avaliacao = generate_avaliacao_explanation(all_results)
    all_results["avaliacao"] = avaliacao
    manager.add_log(scan_id, "=" * 50, "separator")
    for line in avaliacao.split("\n"):
        level = "ok" if line.startswith("  [OK]") else "critical" if line.startswith("  [FALHA]") else "info"
        if line.strip():
            manager.add_log(scan_id, line, level)
    manager.add_log(scan_id, "=" * 50, "separator")

    manager.add_log(scan_id, "[+] Gerando relatorios...", "info")
    all_results["version"] = VERSION
    all_results["target"] = target
    all_results["timestamp"] = datetime.now().isoformat()

    Path(OUTPUT_DIR).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    sf = re.sub(r'[^\w.-]', '_', target)
    html_file = f"{OUTPUT_DIR}/recon_{sf}_{ts}.html"
    txt_file = f"{OUTPUT_DIR}/recon_{sf}_{ts}.txt"

    from core.reporting import generate_reports
    generate_reports(all_results, html_file, txt_file)
    all_results["html_file"] = html_file
    all_results["txt_file"] = txt_file

    manager.add_log(scan_id, f"[+] HTML: {html_file}", "ok")
    manager.add_log(scan_id, f"[+] TXT:  {txt_file}", "ok")
    manager.add_log(scan_id, "=" * 50, "separator")
    manager.add_log(scan_id, "[ RECONHECIMENTO CONCLUIDO ]", "module")

    manager.set_results(scan_id, all_results)
    manager.add_log(scan_id, "[DONE]", "done")

# ---------------------------------------------------------------------------
# Load UI template
# ---------------------------------------------------------------------------

UI_PATH = os.path.join(os.path.dirname(__file__), "web", "ui.html")
try:
    with open(UI_PATH, "r", encoding="utf-8") as f:
        PAGE_TEMPLATE = f.read()
except:
    PAGE_TEMPLATE = "<html><body><h1>PhantomRecon</h1><p>Template not found</p></body></html>"

def get_page():
    page = PAGE_TEMPLATE.replace("{VERSION}", VERSION)
    page = page.replace("{EDITION}", EDITION)
    return page

# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class PhantomHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/report/"):
            raw = unquote(self.path[8:])
            is_pdf = "?print=1" in raw
            fname = raw.replace("?print=1", "")
            try:
                with open(fname, "r", encoding="utf-8") as f:
                    content = f.read()
                if is_pdf:
                    inject = "<script>window.onload=function(){window.print()}</script>"
                    content = content.replace("</head>", inject + "</head>")
                ct = "text/html; charset=utf-8" if fname.endswith(".html") else "text/plain; charset=utf-8"
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            except:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found")
        elif self.path.startswith("/api/log"):
            qs = parse_qs(urlparse(self.path).query)
            sid = int(qs.get("id", [0])[0])
            log_data = manager.get_log(sid)
            done = manager.is_done(sid)
            res = manager.get_results(sid)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"log": log_data, "done": done, "results": res}, ensure_ascii=False, default=str).encode("utf-8"))
        else:
            page = get_page()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(page.encode("utf-8"))

    def do_POST(self):
        if self.path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
            target = data.get("target", "")
            profile = data.get("profile", "aggressive")
            sid = manager.next_id()
            t = threading.Thread(target=run_full_scan, args=(target, sid, profile), daemon=True)
            t.start()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"scan_id": sid}).encode("utf-8"))

    def log_message(self, format, *args):
        pass

# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------

def setup_hostname():
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    entry = "127.0.0.1 phantomrecon"
    try:
        with open(hosts_path, "r") as f:
            if "phantomrecon" not in f.read():
                with open(hosts_path, "a") as f:
                    f.write(f"\n{entry}\n")
                return True
            return True
    except:
        return False

def launch():
    has_host = setup_hostname()
    port = 80 if has_host else 5656
    host = "phantomrecon" if has_host else "127.0.0.1"

    try:
        server = HTTPServer(("0.0.0.0", port), PhantomHandler)
    except PermissionError:
        port = 5656
        host = "127.0.0.1"
        server = HTTPServer(("0.0.0.0", port), PhantomHandler)

    url = f"http://{host}:{port}" if port != 80 else f"http://{host}/"
    print(f"\n  PHANTOMRECON v{VERSION} Free Edition")
    print(f"  {'='*50}")
    print(f"  Interface: {url}")
    if not has_host:
        print(f"  Dica: Execute como Administrador para usar http://phantomrecon/")
    print(f"  {'='*50}\n")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Servidor encerrado.\n")
        server.server_close()
