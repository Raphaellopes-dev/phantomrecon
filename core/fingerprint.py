import json
from utils.network import safe_open, HTTPSession

def module_fingerprint(manager, target, scan_id):
    manager.add_log(scan_id, "[ MODULO: FINGERPRINTING ]", "module")
    result = {}
    if not target.startswith("http"):
        target = "http://" + target
    from urllib.parse import urlparse
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    tech = {}
    waf = None
    cms = None

    manager.add_log(scan_id, "[*] Detectando servidor web...", "info")
    r = safe_open(target, 4)
    if r:
        server = r.headers.get("Server", "")
        powered = r.headers.get("X-Powered-By", "")
        aspnet = r.headers.get("X-AspNet-Version", "")
        cf_ray = r.headers.get("cf-ray", "")
        if server:
            tech["Server"] = server
            manager.add_log(scan_id, f"  Server: {server}", "info")
            if "cloudflare" in server.lower():
                waf = "Cloudflare"
            elif "cloudfront" in server.lower():
                waf = "AWS CloudFront"
        if powered:
            tech["X-Powered-By"] = powered
            manager.add_log(scan_id, f"  X-Powered-By: {powered}", "info")
        if aspnet:
            tech["X-AspNet-Version"] = aspnet
            manager.add_log(scan_id, f"  X-AspNet-Version: {aspnet}", "info")
        if cf_ray:
            waf = "Cloudflare"
            manager.add_log(scan_id, "  Cloudflare detectado (cf-ray header)", "info")

        if server:
            server_lower = server.lower()
            if "apache" in server_lower:
                cms = "Apache HTTP Server"
            elif "nginx" in server_lower:
                cms = "nginx"
            elif "iis" in server_lower:
                cms = "Microsoft IIS"
            elif "litespeed" in server_lower:
                cms = "LiteSpeed"
            elif "caddy" in server_lower:
                cms = "Caddy"
            elif "openresty" in server_lower:
                cms = "OpenResty"

    result["tech"] = tech
    if waf:
        result["waf"] = waf
        manager.add_log(scan_id, f"  [!] WAF detectado: {waf}", "warn")
    if cms:
        result["cms_server"] = cms
        manager.add_log(scan_id, f"  [*] Servidor: {cms}", "info")

    manager.add_log(scan_id, "[*] Verificando WordPress...", "info")
    wp = {}
    wp_checks = [("/wp-json/wp/v2/users", "WP JSON API"), ("/xmlrpc.php", "XML-RPC"),
                 ("/readme.html", "WP readme"), ("/wp-content/", "WP content"),
                 ("/wp-includes/", "WP includes"), ("/wp-admin/", "WP admin"),
                 ("/feed/", "WP feed")]
    for path, label in wp_checks:
        r2 = safe_open(f"{base}{path}", 3)
        if r2:
            wp[path] = {"status": r2.status, "accessible": True, "label": label}
            manager.add_log(scan_id, f"  [*] {label}: {r2.status} (acessivel)", "warn")
            if "users" in path and r2.status == 200:
                try:
                    users = json.loads(r2.read().decode("utf-8", errors="ignore"))
                    wp["wp_users"] = [u.get("name", u.get("slug", "")) for u in users[:5]]
                    manager.add_log(scan_id, f"  [!] Usuarios WordPress expostos: {', '.join(wp['wp_users'])}", "critical")
                except:
                    pass

    if wp:
        result["wordpress"] = wp
        cms_detected = "WordPress"
        result["cms"] = cms_detected
        manager.add_log(scan_id, f"  [+] CMS detectado: {cms_detected}", "ok")

    manager.add_log(scan_id, "[*] Verificando cookies e headers WAF...", "info")
    sess = HTTPSession()
    resp = sess.get(target, timeout=4)
    if resp:
        for k, v in resp.headers.items():
            k_lower = k.lower()
            if k_lower == "set-cookie":
                if "__cfduid" in v or "__cf_bm" in v:
                    waf = "Cloudflare"
                elif "mod_security" in v.lower() or "sucuri" in v.lower():
                    waf = v.split("=")[0]
            if k_lower == "x-sucuri-id":
                waf = "Sucuri"
            if k_lower == "x-powered-by" and v not in tech.get("X-Powered-By", ""):
                tech["X-Powered-By"] = v
        if waf and not result.get("waf"):
            result["waf"] = waf
            manager.add_log(scan_id, f"  [!] WAF detectado: {waf}", "warn")

    result["tech"] = tech
    manager.add_log(scan_id, "[+] Fingerprinting concluido", "ok")
    return result
