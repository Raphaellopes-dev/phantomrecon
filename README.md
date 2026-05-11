# PhantomRecon

**Pentest Recon Toolkit for Windows** — Reconhecimento profissional nativo no Windows, sem WSL, VM ou Kali Linux.

```bash
python main.py scanme.nmap.org
```

## Funcionalidades

- [x] DNS resolution com aliases e IPs
- [x] Ping com análise de TTL (detecção de SO: Linux, Windows, Cisco)
- [x] **Banner grabbing** — versão real dos serviços (ex: `OpenSSH_6.6.1p1`, `Apache/2.4.7`)
- [x] Varredura de portas concorrente (ThreadPoolExecutor — 50 threads simultâneas)
- [x] Perfis: **quick** (26 portas comuns) e **full** (1024+ portas)
- [x] Classificação de exposição sensível (RDP, SMB, MySQL, Redis, etc.)
- [x] Análise de headers HTTP com auditoria de segurança (HSTS, CSP, XSS, etc.)
- [x] Verificação SSL/TLS com dados do certificado (validade, emissor, subject)
- [x] Enumeração de registros DNS (A, MX, NS, TXT, AAAA, CNAME)
- [x] **Relatório TXT** organizado para documentação
- [x] **Relatório HTML** profissional com tema dark hacker
- [x] Modo interativo e CLI direta

## Instalação

```bash
git clone https://github.com/Raphaellopes-dev/phantomrecon.git
cd phantomrecon
pip install rich cryptography
```

## Uso

```bash
# Scan rapido (26 portas comuns)
python main.py scanme.nmap.org

# Scan completo (1024+ portas)
python main.py scanme.nmap.org full

# Modo interativo
python main.py
```

## Exemplo

```
  ╔══════════════════════════════════════════════════════╗
  ║                    PHANTOMRECON                      ║
  ║           Pentest Recon Toolkit for Windows           ║
  ╚══════════════════════════════════════════════════════╝

  [#] Alvo: scanme.nmap.org | Perfil: quick

  ┌───────┬─────────┬────────────────────────────────────┬────────────┐
  │ Porta │ Servico │ Versao                             │ Status     │
  ├───────┼─────────┼────────────────────────────────────┼────────────┤
  │  22   │ SSH     │ SSH-2.0-OpenSSH_6.6.1p1 Ubuntu     │ Aberta     │
  │  80   │ HTTP    │ HTTP/1.1 200 OK                    │ Aberta     │
  └───────┴─────────┴────────────────────────────────────┴────────────┘

  [+] Relatorio TXT: reports/recon_scanme.nmap.org_20260511_*.txt
  [+] Relatorio HTML: reports/recon_scanme.nmap.org_20260511_*.html
```

## Relatório HTML

Tema escuro profissional (preto + verde #00ff88), layout responsivo com cards, tabelas de portas, headers HTTP, dados SSL/TLS. Pronto para compartilhar ou anexar em relatórios.

## Requisitos

- Python 3.7+
- Windows (não testado em Linux)
- `rich` (pip install rich) — para terminal colorido
- `cryptography` (opcional) — para dados detalhados de SSL

## Licença

MIT
