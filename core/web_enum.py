from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from config import COMMON_DIRS, COMMON_ADMIN
from utils.network import safe_open, HTTPSession, CrawlParser

def module_web(manager, target, scan_id):
    manager.add_log(scan_id, "[ MODULO: ENUMERACAO WEB ]", "module")
    result = {}
    if not target.startswith("http"):
        target = "http://" + target
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    dirs_found = []
    adm_found = []

    manager.add_log(scan_id, "[*] Escaneando diretorios...", "info")
    def check_path(path):
        r = safe_open(f"{base}/{path}", 3)
        if r and r.status in (200, 301, 302, 401, 403):
            return (path, r.status, r.headers.get("Content-Length", "?"), "MEDIUM")
        return None
    with ThreadPoolExecutor(max_workers=15) as ex:
        for f in as_completed({ex.submit(check_path, p): p for p in COMMON_DIRS}):
            try:
                r = f.result(timeout=5)
                if r:
                    dirs_found.append(r)
                    color = "critical" if r[0] in COMMON_ADMIN else "ok"
                    manager.add_log(scan_id, f"  [{r[1]}] /{r[0]}", color)
            except:
                pass
    result["directories"] = dirs_found
    manager.add_log(scan_id, f"[+] Diretorios: {len(dirs_found)}", "ok" if dirs_found else "info")

    manager.add_log(scan_id, "[*] Procurando paineis admin...", "info")
    def check_admin(path):
        r = safe_open(f"{base}/{path}", 3)
        if r and r.status in (200, 401, 403):
            return (path, r.status, "HIGH")
        return None
    with ThreadPoolExecutor(max_workers=8) as ex:
        for f in as_completed({ex.submit(check_admin, p): p for p in COMMON_ADMIN}):
            try:
                r = f.result(timeout=5)
                if r:
                    adm_found.append(r)
                    manager.add_log(scan_id, f"  [!] Painel: /{r[0]} ({r[1]})", "critical")
            except:
                pass
    result["admin_panels"] = adm_found

    manager.add_log(scan_id, "[*] Detectando tecnologias (basico)...", "info")
    tech = {}
    r = safe_open(target, 4)
    if r:
        for k in ["Server", "X-Powered-By", "X-AspNet-Version"]:
            v = r.headers.get(k)
            if v:
                tech[k] = v
                manager.add_log(scan_id, f"  {k}: {v}", "info")
    result["tech"] = tech

    manager.add_log(scan_id, "[+] Enumeracao web concluida", "ok")
    return result

def module_crawl(manager, target, scan_id):
    manager.add_log(scan_id, "[ MODULO: CRAWLER WEB ]", "module")
    result = {}
    if not target.startswith("http"):
        target = "http://" + target
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    manager.add_log(scan_id, "[*] Baixando pagina inicial...", "info")
    sess = HTTPSession()
    resp = sess.get(target)
    if not resp or resp.status >= 400:
        manager.add_log(scan_id, "[-] Nao foi possivel acessar a pagina inicial", "error")
        return result

    body = resp.read().decode("utf-8", errors="ignore")
    parser = CrawlParser(target)
    parser.feed(body)

    links = list(parser.links)
    if links:
        manager.add_log(scan_id, f"[+] Links encontrados: {len(links)}", "info")
        for l in list(links)[:8]:
            manager.add_log(scan_id, f"    {l}", "info")
    result["links"] = links

    forms = parser.forms
    if forms:
        manager.add_log(scan_id, f"[+] Formularios encontrados: {len(forms)}", "info")
        for f in forms[:5]:
            fields_list = []
            for inp in f["fields"]:
                val = inp.get("value", "")
                if val and inp.get("type") == "hidden" and len(val) > 5:
                    fields_list.append(f"{inp['name']}={val[:12]}...")
                elif val:
                    fields_list.append(f"{inp['name']}:{inp['type']}={val}")
                else:
                    fields_list.append(f"{inp['name']}:{inp.get('type','?')}")
            fields_str = ", ".join(fields_list)
            manager.add_log(scan_id, f"    {f['method']} {f['action']} -> [{fields_str}]", "info")
            hidden_with_val = [inp for inp in f["fields"] if inp.get("type") == "hidden" and inp.get("value")]
            if hidden_with_val:
                manager.add_log(scan_id, f"    [*] Tokens CSRF detectados: {len(hidden_with_val)} campo(s) oculto(s)", "info")
    result["forms"] = forms

    comments = [c for c in parser.comments if len(c) > 10]
    if comments:
        manager.add_log(scan_id, f"[+] Comentarios HTML sensiveis: {len(comments)}", "warn")
        for c in comments[:5]:
            manager.add_log(scan_id, f"    <!-- {c[:80]} -->", "warn")
    result["comments"] = comments

    manager.add_log(scan_id, "[*] Seguindo links internos (max 5)...", "info")
    crawled_urls = [target]
    internal = [l for l in links if parsed.netloc in l and l not in crawled_urls][:5]
    for url in internal:
        r2 = sess.get(url, timeout=4)
        if r2 and r2.status < 400:
            body2 = r2.read().decode("utf-8", errors="ignore")
            p2 = CrawlParser(url)
            p2.feed(body2)
            for f in p2.forms:
                if f not in forms:
                    forms.append(f)
            for c in p2.comments:
                if c not in comments and len(c) > 10:
                    comments.append(c)
            crawled_urls.append(url)
            manager.add_log(scan_id, f"    + {url}", "info")
    result["crawled_urls"] = crawled_urls
    result["forms"] = forms
    result["comments"] = comments

    manager.add_log(scan_id, "[+] Crawler concluido", "ok")
    return result
