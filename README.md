# PhantomRecon Free 

**Offensive Security Toolkit for Windows** — Nativo, zero dependencias, sem WSL/VM/Kali.

```bash
python main.py
```

Abre interface web em `http://127.0.0.1:5656/` (ou `http://phantomrecon/` como Admin).

## Arquitetura

```
main.py              → entry point
server.py            → HTTP server, API, ScanManager, scan orchestrator
config.py            → constantes, portas, CVE DB, wordlists, modos
core/
├── recon.py         → DNS, ping, port scan (50 threads), banner, SSL, CVE match
├── web_enum.py      → diretorios, admin panels, crawler HTML, formularios
├── fingerprint.py   → detecta WAF, CMS, servidor web, tecnologias
├── vuln.py          → auditoria headers de seguranca
├── exploit.py       → Apache CVE, WordPress enum, SQLi/XSS, LFI, default creds
└── reporting.py     → relatorios HTML + TXT
utils/
├── network.py       → HTTP session, crawler parser, port scanner
└── helpers.py       → security score, avaliacao final
web/
└── ui.html          → frontend standalone (CSS + JS)
```

## Features

- **Recon** — DNS, ping com TTL+OS, port scan, banner grab, SSL/TLS, CVE matching
- **Web Enum** — diretorios, admin panels, tecnologia fingerprint
- **Crawler** — parse HTML, descobre forms, CSRF tokens, comentarios sensiveis
- **Fingerprint** — detecta Apache, nginx, IIS, Cloudflare, WordPress, WAF
- **Vuln Check** — headers de seguranca, exposicao de portas
- **Exploit** — Apache CVE path traversal, WordPress user enum, SQLi, XSS, LFI, default creds
- **Security Score** — 0-100 com Grade A+/A/B/C/D/F
- **Confidence** — CONFIRMED / LIKELY / SUSPECTED / LOW_CONFIDENCE
- **Severity** — CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Modos** — SAFE (recon) / AUDIT (recon+web+vuln) / AGGRESSIVE (tudo)
- **Relatorios** — HTML + PDF (print-to-browser) com Avaliacao Final em portugues
- **Matrix Rain UI** — terminal live polling, tema dark hacker

## Como usar

1. `python main.py`
2. Abre browser em `http://127.0.0.1:5656/`
3. Digita o dominio (ex: `scanme.nmap.org`)
4. Escolhe perfil: Seguro / Auditoria / Agressivo
5. Acompanha ao vivo no terminal web
6. Ao final, baixa HTML + PDF

## Requisitos

- Python 3.7+
- Windows
- Opcional: `pip install cryptography` para dados SSL detalhados

## Licenca

MIT
