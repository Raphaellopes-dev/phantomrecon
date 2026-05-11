# PhantomRecon

**Pentest Recon Toolkit for Windows** — Reconhecimento profissional nativo no Windows, sem WSL, VM ou Kali Linux.

```
python main.py scanme.nmap.org
```

## Funcionalidades

- [x] DNS resolution com aliases e IPs
- [x] Ping com análise de TTL (detecção de SO: Linux, Windows, Cisco)
- [x] Varredura de portas concorrente (ThreadPoolExecutor — 50 threads)
- [x] Perfis: **quick** (26 portas comuns) e **full** (1024+ portas)
- [x] Banner grabbing em serviços HTTP
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

## Exemplo de saída (terminal)

```
  ╔══════════════════════════════════════════════════════╗
  ║                    PHANTOMRECON                      ║
  ║           Pentest Recon Toolkit for Windows           ║
  ║                    v2.0.0                            ║
  ║       by Raphael Lopes                              ║
  ╚══════════════════════════════════════════════════════╝

  [#] Alvo: scanme.nmap.org | Perfil: quick

  ┌────────────────────── RESOLUCAO DNS ──────────────────────┐
  │  Host: scanme.nmap.org   IPs: 45.33.32.156               │
  └───────────────────────────────────────────────────────────┘

  ─── Portas Abertas ───
  ┌───────┬─────────┬────────┐
  │ Porta │ Servico │ Status │
  ├───────┼─────────┼────────┤
  │  22   │ SSH     │ Aberta │
  │  80   │ HTTP    │ Aberta │
  └───────┴─────────┴────────┘
```

## Relatório HTML

O HTML gerado possui:
- Tema escuro profissional (preto + verde #00ff88)
- Layout responsivo com cards e grades
- Código do alvo, portas, HTTP headers, SSL/TLS
- Pronto para compartilhar ou anexar em relatórios

## Requisitos

- Python 3.7+
- Windows (não testado em Linux)
- rich (pip install rich)
- cryptography (opcional — para dados detalhados de SSL)

## Licença

MIT
