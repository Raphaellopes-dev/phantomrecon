# PhantomRecon

**Pentest Recon Toolkit for Windows** — Reconhecimento profissional nativo no Windows, sem WSL, VM ou Kali Linux.

```
python main.py scanme.nmap.org
```

## Modo Web UI (recomendado)

```bash
python main.py --ui
```

Abre uma interface profissional no navegador (http://127.0.0.1:5656):

- Input de target com perfil quick/full
- Resultados em cards com tema dark hacker
- Tabela de portas com banner grabbing
- Auditoria de headers HTTP
- Dados SSL/TLS
- Download de relatorios TXT e HTML

## Modo CLI

```bash
python main.py scanme.nmap.org
python main.py scanme.nmap.org full
```

## Funcionalidades

- [x] Interface web local (--ui) — zero bugs de terminal
- [x] DNS resolution com aliases e IPs
- [x] Ping com analise de TTL (detecção de SO)
- [x] Banner grabbing — versão real dos servicos (OpenSSH_6.6.1p1, Apache/2.4.7)
- [x] Varredura concorrente (50 threads)
- [x] Perfis: quick (26 portas) e full (1024+)
- [x] Classificação de exposicao sensivel
- [x] Auditoria de headers HTTP (HSTS, CSP, XSS, etc.)
- [x] Verificacao SSL/TLS com dados do certificado
- [x] Enumeracao de registros DNS (A, MX, NS, TXT)
- [x] Relatorio TXT + HTML profissional

## Requisitos

- Python 3.7+
- Windows
- Zero dependencias obrigatorias (tudo built-in)
- Opcional: `pip install cryptography` para dados SSL detalhados

## Licenca

MIT
