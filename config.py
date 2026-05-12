EDITION = "Free Edition"
OUTPUT_DIR = "reports"

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "Clickjacking"),
    ("x-xss-protection", "XSS"),
    ("x-content-type-options", "MIME-sniff"),
    ("referrer-policy", "Referrer"),
    ("permissions-policy", "Permissions"),
]

SENSITIVE_PORTS = [3389, 445, 5985, 5986, 1433, 3306, 6379, 27017]
BANNER_PORTS = {21, 22, 25, 80, 110, 143, 443, 8080, 8443}
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
              1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 27017]

COMMON_DIRS = [
    "admin", "login", "wp-admin", "wp-login", "administrator", "dashboard",
    "phpmyadmin", "pma", "manager", "panel", "cpanel", "api", "v1", "v2",
    "backup", "backups", "bak", "old", "test", "tests", "dev", "config",
    "configuration", "setup", "install", "uploads", "upload", "files",
    "images", "img", "css", "js", "assets", "static", "private", "restricted",
    "secret", "hidden", "internal", "docs", "documentation", "sitemap.xml",
    "robots.txt", ".git", ".env", "README.md", "CHANGELOG.md", "license.txt",
    "xmlrpc.php", ".htaccess", "server-status", "server-info",
]

COMMON_ADMIN = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "dashboard", "panel", "cpanel", "manager", "backend", "admin.php",
    "admin/login", "user/login", "signin", "login.php", "index.php?login",
    "adm", "admin_area", "adminpanel",
]

LFI_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/issue",
    "C:/Windows/win.ini", "C:/Windows/system32/drivers/etc/hosts",
    "C:/boot.ini", "C:/inetpub/wwwroot/web.config",
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
    ("admin", "admin123"), ("admin", "1234"), ("admin", "12345"),
    ("admin", "admin1"), ("admin", "administrator"), ("admin", "root"),
    ("admin", "test"), ("admin", "temp"), ("admin", "admin1234"),
    ("root", "root"), ("root", "toor"), ("root", "admin"),
    ("user", "user"), ("user", "password"), ("guest", "guest"),
    ("test", "test"), ("admin", ""), ("admin", "senha"),
    ("administrator", "administrator"), ("administrator", "admin"),
]

SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "1' --", "' UNION SELECT 1--", "'; DROP TABLE--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", '"><script>alert(1)</script>', "<img src=x onerror=alert(1)>"]

SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "unclosed quotation", "odbc driver",
    "you have an error in your sql", "warning: mysql",
    "quotation mark", "syntax error",
]

SEVERITY = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
}

SEVERITY_LABEL = {
    5: "CRITICAL", 4: "HIGH", 3: "MEDIUM", 2: "LOW", 1: "INFO",
}

CONFIDENCE = {
    "CONFIRMED": 5, "LIKELY": 4, "SUSPECTED": 3, "LOW_CONFIDENCE": 2,
}

CVE_DB = {
    "Apache": {
        "2.4.49": {"cve": "CVE-2021-41773", "desc": "Path traversal em Apache 2.4.49 via /cgi-bin/.%2e/%2e%2e/", "critical": True, "exploit_path": "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"},
        "2.4.50": {"cve": "CVE-2021-42013", "desc": "Path traversal em Apache 2.4.50 via /cgi-bin/.%%32%65/", "critical": True, "exploit_path": "/cgi-bin/.%%32%65/%%32%65/%%32%65/etc/passwd"},
    },
    "OpenSSH": {
        "<7.4": {"cve": "CVE-2016-6210", "desc": "User enumeration via timing attack no OpenSSH < 7.4", "critical": False},
        "<7.7": {"cve": "CVE-2018-15473", "desc": "User enumeration via timing attack no OpenSSH < 7.7", "critical": False},
    },
}

MODE_MODULES = {
    "safe": ["recon"],
    "audit": ["recon", "web_enum", "crawl", "fingerprint", "vuln"],
    "aggressive": ["recon", "web_enum", "crawl", "fingerprint", "vuln", "exploit"],
}
