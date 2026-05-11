#!/usr/bin/env python3
"""
PhantomRecon — Pentest recon toolkit for Windows
by Raphael Lopes
"""

import sys
import time
import socket
import subprocess
import json
import os
from datetime import datetime

VERSION = "1.0.0"
BANNER = f"""
{'='*60}
  PHANTOMRECON v{VERSION}
  Toolkit de reconhecimento para Windows
  by Raphael Lopes — github.com/Raphaellopes-dev
{'='*60}
"""

def log(msg, status="info"):
    symbols = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]", "highlight": "[#]"}
    s = symbols.get(status, "[*]")
    print(f"  {s} {msg}")
    time.sleep(0.15)

def separator(title=None):
    if title:
        print(f"\n  {'-'*50}")
        print(f"  [>] {title}")
        print(f"  {'-'*50}")
    else:
        print(f"\n  {'-'*50}\n")

def resolve_dns(target):
    separator("RESOLUCAO DNS")
    try:
        result = socket.gethostbyname_ex(target)
        log(f"Host: {result[0]}", "ok")
        log(f"Aliases: {', '.join(result[1]) if result[1] else 'Nenhum'}", "info")
        log(f"IPs: {', '.join(result[2])}", "highlight")
        return result[2]
    except socket.gaierror:
        log(f"Nao foi possivel resolver {target}", "err")
        return []

def ping_host(ip):
    separator("PING / STATUS")
    try:
        result = subprocess.run(["ping", "-n", "2", ip], capture_output=True, text=True, timeout=8, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "ms" in line.lower() and "tempo" in line.lower():
                    log(f"Host respondeu: {line.strip()}", "ok")
                    return True
            log(f"Host ativo (sem dados de tempo)", "ok")
            return True
        else:
            log(f"Host nao respondeu ping", "warn")
            return False
    except:
        log(f"Erro ao executar ping", "err")
        return False

def scan_ports(target, ports=None):
    separator("VARREDURA DE PORTAS")
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5800, 5900, 5985, 5986, 6379, 8080, 8443, 9000, 9090, 10000, 11211, 27017, 50070]

    common = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5800: "VNC", 5900: "VNC", 5985: "WinRM-HTTP",
        5986: "WinRM-HTTPS", 6379: "Redis", 8080: "HTTP-Proxy",
        8443: "HTTPS-Alt", 27017: "MongoDB", 50070: "Hadoop"
    }

    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                service = common.get(port, "Desconhecido")
                log(f"Porta {port}/TCP aberta - {service}", "ok" if port not in [3389, 445, 5985, 5986] else "warn")
                open_ports.append((port, service))
        except:
            pass

    if not open_ports:
        log("Nenhuma porta aberta encontrada", "warn")
    return open_ports

def check_http(target, port=80):
    separator("ANALISE HTTP")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        s.send(f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: PhantomRecon/1.0\r\nConnection: close\r\n\r\n".encode())
        response = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()

        headers = response.split("\r\n")
        log(f"Resposta HTTP recebida ({len(response)} bytes)", "ok")

        important_headers = ["server", "x-powered-by", "x-aspnet-version", "location",
                            "set-cookie", "www-authenticate", "strict-transport-security",
                            "content-security-policy", "x-frame-options", "x-xss-protection"]

        found = []
        for h in headers:
            for ih in important_headers:
                if h.lower().startswith(ih):
                    found.append(h.strip())
                    log(f"  {h.strip()}", "highlight" if "server" in h.lower() or "powered" in h.lower() else "info")

        if not found:
            log("Nenhum header de seguranca encontrado", "warn")
        else:
            missing_security = [h for h in ["strict-transport-security", "content-security-policy", "x-frame-options", "x-xss-protection"] if not any(h in f.lower() for f in found)]
            if missing_security:
                log(f"Faltam headers de seguranca: {', '.join(missing_security)}", "warn")

        return response
    except Exception as e:
        log(f"Erro na requisicao HTTP: {str(e)}", "err")
        return None

def check_https(target, port=443):
    separator("ANALISE SSL/TLS")
    import ssl
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=target)
        ss.connect((target, port))
        log(f"Conexao SSL estabelecida com {target}:{port}", "ok")
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert_der = ss.getpeercert(binary_form=True)
            cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
            subject = cert_obj.subject.rfc4514_string()
            issuer = cert_obj.issuer.rfc4514_string()
            exp = cert_obj.not_valid_after
            if exp.tzinfo is not None:
                exp = exp.replace(tzinfo=None)
            exp_str = exp.strftime("%Y-%m-%d %H:%M:%S")
            log(f"Subject: {subject}", "info")
            log(f"Emissor: {issuer}", "info")
            log(f"Validade: {exp_str}", "highlight" if exp > datetime.utcnow() else "err")
            ss.close()
            return {"subject": subject, "issuer": issuer, "expires": exp_str}
        except ImportError:
            log("Cryptography opcional instalavel: pip install cryptography", "warn")
            cert = ss.getpeercert()
            if cert:
                log("Certificado SSL presente e valido", "ok")
            ss.close()
            return {"status": "ssl active"}
    except Exception as e:
        log(f"Erro SSL: {str(e)}", "err")
        try:
            s.close()
        except:
            pass
    return None

def check_dns_zone(target):
    separator("REGISTROS DNS")
    try:
        result = subprocess.run(["nslookup", target], capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        lines = [l.strip() for l in result.stdout.split("\n") if l.strip()]
        for line in lines:
            if any(kw in line.lower() for kw in ["name", "address", "canonical", "aliases", "mx", "ns"]):
                if target.lower() in line.lower():
                    log(f"  {line}", "info")
        log("Consulta DNS concluida", "ok")
    except subprocess.TimeoutExpired:
        log("Consulta DNS excedeu tempo limite", "warn")
    except:
        log("Erro na consulta DNS", "err")

def generate_report(target, ips, ports, http_data, https_data, output_dir="reports"):
    separator("GERANDO RELATORIO")
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/recon_{target}_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"{'='*60}\n")
        f.write(f"  PHANTOMRECON v{VERSION} — Relatorio de Reconhecimento\n")
        f.write(f"  Alvo: {target}\n")
        f.write(f"  Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write(f"  Operador: Raphael Lopes\n")
        f.write(f"{'='*60}\n\n")

        f.write(f"[+] Alvo: {target}\n")
        if ips:
            f.write(f"[+] IPs: {', '.join(ips)}\n")
        f.write(f"\n")

        if ports:
            f.write(f"{'-'*50}\n")
            f.write(f"PORTAS ABERTAS\n")
            f.write(f"{'-'*50}\n")
            for port, service in ports:
                f.write(f"  {port}/TCP  {service}\n")
            f.write(f"\n")

        if http_data:
            f.write(f"{'-'*50}\n")
            f.write(f"HEADERS HTTP\n")
            f.write(f"{'-'*50}\n")
            f.write(http_data[:2000] + "\n\n")

        if https_data:
            f.write(f"{'-'*50}\n")
            f.write(f"SSL/TLS\n")
            f.write(f"{'-'*50}\n")
            f.write(json.dumps(https_data, indent=2) + "\n\n")

        f.write(f"{'='*60}\n")
        f.write(f"  Relatorio gerado automaticamente pelo PhantomRecon\n")
        f.write(f"  github.com/Raphaellopes-dev\n")
        f.write(f"{'='*60}\n")

    log(f"Relatorio salvo: {filename}", "ok")
    return filename

def interactive_mode():
    separator()
    target = input("  [Target] Digite o dominio ou IP: ").strip()
    if not target:
        log("Target invalido", "err")
        return

    print()
    log(f"Iniciando reconhecimento em: {target}", "highlight")
    log(f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", "info")
    separator()

    ips = resolve_dns(target)
    main_ip = ips[0] if ips else target

    ping_host(main_ip)
    open_ports = scan_ports(main_ip)

    http_data = None
    https_data = None
    for port, service in open_ports:
        if port == 80:
            http_data = check_http(target, 80)
        elif port == 443:
            https_data = check_https(target, 443)
        elif port in [8080, 8443]:
            if port == 8080:
                http_data = check_http(target, 8080)
            elif port == 8443:
                https_data = check_https(target, 8443)

    if not http_data and not https_data:
        log("Testando HTTP na porta 80...", "info")
        http_data = check_http(target, 80)

    check_dns_zone(target)

    report = generate_report(target, ips, open_ports, http_data, https_data)

    separator("RESUMO")
    log(f"Alvo: {target}", "ok")
    log(f"IPs encontrados: {len(ips)}", "ok")
    log(f"Portas abertas: {len(open_ports)}", "ok")
    log(f"Relatorio: {report}", "highlight")
    separator()

def main():
    print(BANNER)

    if len(sys.argv) > 1:
        target = sys.argv[1]
        log(f"Iniciando reconhecimento em: {target}", "highlight")
        ips = resolve_dns(target)
        main_ip = ips[0] if ips else target
        ping_host(main_ip)
        open_ports = scan_ports(main_ip)
        http_data = None
        https_data = None
        for port, service in open_ports:
            if port in [80, 8080]: http_data = check_http(target, port)
            if port in [443, 8443]: https_data = check_https(target, port)
        if not http_data and not https_data:
            http_data = check_http(target, 80)
        check_dns_zone(target)
        generate_report(target, ips, open_ports, http_data, https_data)
        print(f"\n  {'-'*50}")
        log("Reconhecimento concluido!")
    else:
        interactive_mode()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  [!] Operacao cancelada pelo usuario\n")
        sys.exit(0)
