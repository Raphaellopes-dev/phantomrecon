# PhantomRecon

**Toolkit de reconhecimento para Windows** — Pentest recon nativo no Windows, sem precisar de WSL, VM ou Kali Linux.

## Funcionalidades

- [x] Resolução DNS (A, aliases)
- [x] Ping / status do host
- [x] Varredura de portas (30+ portas comuns)
- [x] Identificação de serviço por porta
- [x] Análise de headers HTTP (segurança, server, etc.)
- [x] Verificação SSL/TLS (certificado, validade)
- [x] Consulta de registros DNS (nslookup)
- [x] Relatório em .txt organizado

## Uso

```bash
python main.py scanme.nmap.org
```

Ou modo interativo:
```bash
python main.py
```

## Instalação

```bash
git clone https://github.com/Raphaellopes-dev/phantomrecon.git
cd phantomrecon
# Opcional: SSL detalhado
pip install cryptography
```

## Requisitos

- Python 3.7+
- Windows (não testado em Linux)
- Nenhuma dependência obrigatória (tudo built-in)

## Exemplo de saída

```
============================================================
  PHANTOMRECON v1.0.0
  Toolkit de reconhecimento para Windows
  by Raphael Lopes
============================================================

  [#] Iniciando reconhecimento em: scanme.nmap.org

  --------------------------------------------------
  [>] RESOLUCAO DNS
  --------------------------------------------------
  [+] Host: scanme.nmap.org
  [#] IPs: 45.33.32.156

  --------------------------------------------------
  [>] VARREDURA DE PORTAS
  --------------------------------------------------
  [+] Porta 22/TCP aberta - SSH
  [+] Porta 80/TCP aberta - HTTP
```

## Licença

MIT
