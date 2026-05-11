import ssl as sslmod
import socket
import time
from urllib.request import urlopen, Request
from urllib.parse import urljoin
from urllib.error import HTTPError
from html.parser import HTMLParser
from config import BANNER_PORTS

def safe_open(url, timeout=4):
    ctx = sslmod.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = sslmod.CERT_NONE
    def _try(method):
        try:
            req = Request(url, method=method)
            req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            req.add_header("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7")
            return urlopen(req, timeout=timeout, context=ctx)
        except:
            return None
    r = _try("HEAD")
    if r is None:
        r = _try("GET")
    return r

def timed_urlopen(url_or_req, timeout=4):
    ctx = sslmod.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = sslmod.CERT_NONE
    try:
        if isinstance(url_or_req, Request):
            req = url_or_req
            if not req.headers.get("User-Agent"):
                req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            if not req.headers.get("Accept"):
                req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            return urlopen(req, timeout=timeout, context=ctx)
        return urlopen(url_or_req, timeout=timeout, context=ctx)
    except:
        return None

class HTTPSession:
    def __init__(self):
        self.ctx = sslmod.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = sslmod.CERT_NONE
        self.cookies = {}
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        }

    def _save_cookies(self, resp):
        raw = resp.headers.get("Set-Cookie")
        if raw:
            for entry in raw.split(","):
                if "=" in entry:
                    k, v = entry.split("=", 1)
                    self.cookies[k.strip()] = v.split(";")[0].strip()

    def request(self, url, method="GET", data=None, timeout=5):
        req = Request(url, method=method, data=data)
        for k, v in self.headers.items():
            req.add_header(k, v)
        if self.cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        try:
            resp = urlopen(req, timeout=timeout, context=self.ctx)
            self._save_cookies(resp)
            return resp
        except HTTPError as e:
            self._save_cookies(e)
            return e
        except:
            return None

    def get(self, url, timeout=5):
        return self.request(url, method="GET", timeout=timeout)

    def post(self, url, data, timeout=5):
        if isinstance(data, dict):
            from urllib.parse import urlencode
            data = urlencode(data).encode()
        return self.request(url, method="POST", data=data, timeout=timeout)

class CrawlParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self.inputs = []
        self.comments = []
        self.scripts = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and "href" in d:
            self.links.add(urljoin(self.base_url, d["href"].split("#")[0].split("?")[0]))
        if tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, d.get("action", "")),
                "method": d.get("method", "GET").upper(),
                "fields": [],
            }
            self.forms.append(self._current_form)
        if tag == "input" and self._current_form is not None:
            field = {"name": d.get("name", ""), "type": d.get("type", "text")}
            if "value" in d:
                field["value"] = d["value"]
            self._current_form["fields"].append(field)
        if tag == "script" and "src" in d:
            self.scripts.append(d["src"])
        if tag in ("meta", "link") and "content" in d:
            self.inputs.append(d.get("content", ""))

    def handle_comment(self, data):
        c = data.strip()
        if c and len(c) > 3:
            self.comments.append(c)

    def handle_data(self, data):
        t = data.strip()
        if t and len(t) > 50 and any(k in t.lower() for k in ["user", "pass", "sql", "query", "select", "admin"]):
            self.inputs.append(t.strip()[:200])

def check_port(main_ip, port, target=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        if s.connect_ex((main_ip, port)) == 0:
            from config import COMMON_PORTS
            svc = COMMON_PORTS.get(port, "Desconhecido")
            banner = None
            if port in BANNER_PORTS:
                try:
                    bs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    bs.settimeout(2)
                    bs.connect((main_ip, port))
                    if port in (80, 8080):
                        host = target or main_ip
                        bs.send(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    time.sleep(0.3)
                    raw = bs.recv(256).decode("utf-8", errors="ignore").strip()[:80]
                    if "\n" in raw:
                        raw = raw.split("\n")[0].strip()
                    if raw:
                        banner = raw
                    bs.close()
                except:
                    pass
            s.close()
            return (port, svc, banner)
        s.close()
    except:
        pass
    return None
