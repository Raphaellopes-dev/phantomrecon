#!/usr/bin/env python3
"""
PhantomRecon v2.0 — Professional pentest recon toolkit for Windows
by Raphael Lopes — github.com/Raphaellopes-dev
"""

import sys, time, socket, subprocess, json, os, ipaddress, re
from datetime import datetime, UTC
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.syntax import Syntax
    from rich import box
    from rich.text import Text
    RICH_OK = True
except ImportError:
    RICH_OK = False

VERSION = "2.1.0"
OUTPUT_DIR = "reports"

console = Console() if RICH_OK else None

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5800: "VNC", 5900: "VNC", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 27017: "MongoDB", 50070: "Hadoop"
}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "Clickjacking",
    "x-xss-protection": "XSS",
    "x-content-type-options": "MIME-sniff",
    "referrer-policy": "Referrer",
    "permissions-policy": "Permissions"
}

BANNER = f"""
[bold green]
  ╔══════════════════════════════════════════════════════╗
  ║                    PHANTOMRECON                      ║
  ║           Pentest Recon Toolkit for Windows           ║
  ║                    v{VERSION}                        ║
  ║       by Raphael Lopes — github.com/Raphaellopes-dev  ║
  ╚══════════════════════════════════════════════════════╝
[/bold green]
"""

def cprint(text, style=""):
    if RICH_OK:
        console.print(text, style=style)
    else:
        clean = re.sub(r'\[/?\w+\]', '', str(text))
        print(clean)

def panel(title, content, border="green"):
    if RICH_OK:
        cprint(Panel(content, title=title, border_style=border, box=box.ROUNDED))
    else:
        print(f"\n--- {title} ---")
        print(content)

def step_msg(msg, status="info"):
    symbols = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]", "highlight": "[#]"}
    s = symbols.get(status, "[*]")
    styles = {"info": "cyan", "ok": "bold green", "warn": "bold yellow", "err": "bold red", "highlight": "bold blue"}
    st = styles.get(status, "")
    cprint(f"  {s} {msg}", st)
    time.sleep(0.1)

def os_from_ttl(ttl):
    if ttl <= 64: return "Linux/Unix"
    if ttl <= 128: return "Windows"
    if ttl <= 255: return "Cisco/Network"
    return "Desconhecido"

def resolve_dns(target):
    panel("RESOLUCAO DNS", f"Resolvendo: [bold cyan]{target}[/bold cyan]")
    try:
        result = socket.gethostbyname_ex(target)
        ips = result[2]
        text = f"  Host: [bold]{result[0]}[/bold]\n"
        if result[1]:
            text += f"  Aliases: {', '.join(result[1])}\n"
        text += f"  IPs: [bold green]{', '.join(ips)}[/bold green]"
        panel("Resultado DNS", text)
        return ips
    except socket.gaierror:
        step_msg(f"Nao foi possivel resolver {target}", "err")
        return []

def ping_host(ip):
    panel("PING / STATUS", f"Testando: [bold cyan]{ip}[/bold cyan]")
    try:
        result = subprocess.run(["ping", "-n", "2", ip], capture_output=True, text=True, timeout=8, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode == 0:
            ttl_match = re.search(r"TTL=(\d+)", result.stdout, re.IGNORECASE)
            time_match = re.search(r"(tempo|time)[=<]\s*(\d+)ms", result.stdout, re.IGNORECASE)

            info = ["[bold green]Host ativo[/bold green]"]
            if time_match: info.append(f"Latencia: {time_match.group(2)}ms")
            if ttl_match:
                ttl = int(ttl_match.group(1))
                info.append(f"TTL: {ttl} [bold yellow]({os_from_ttl(ttl)})[/bold yellow]")

            panel("Resultado Ping", "\n".join(info))
            return True
        else:
            step_msg("Host nao respondeu ping", "warn")
            return False
    except subprocess.TimeoutExpired:
        step_msg("Ping excedeu tempo limite", "warn")
        return False
    except:
        step_msg("Erro ao executar ping", "err")
        return False

def scan_ports(target, profile="quick"):
    if profile == "quick":
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 27017]
    elif profile == "full":
        ports = list(range(1, 1025)) + [1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986,
                                         6379, 8080, 8443, 9100, 10000, 11211, 27017, 50070]
    else:
        ports = COMMON_PORTS.keys()

    step_msg(f"Iniciando varredura ({profile}, {len(ports)} portas)", "info")

    open_ports = []
    total = len(ports)
    banner_ports = {21, 22, 25, 80, 110, 143, 443, 8080, 8443}

    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            r = s.connect_ex((target, port))
            if r == 0:
                service = COMMON_PORTS.get(port, "Desconhecido")
                banner = None
                if port in banner_ports:
                    try:
                        bs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        bs.settimeout(2)
                        bs.connect((target, port))
                        if port in (80, 8080):
                            bs.send(f"GET / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: PR/2.0\r\n\r\n".encode())
                        time.sleep(0.3)
                        raw = bs.recv(256).decode("utf-8", errors="ignore").strip()[:80]
                        if "\n" in raw: raw = raw.split("\n")[0].strip()
                        if raw: banner = raw
                        bs.close()
                    except:
                        pass
                s.close()
                return (port, service, banner)
            s.close()
        except:
            pass
        return None

    if RICH_OK:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as prog:
            task = prog.add_task(f"[cyan]Escaneando {target}...[/cyan]", total=total)
            with ThreadPoolExecutor(max_workers=50) as ex:
                futures = {ex.submit(check, p): p for p in ports}
                for f in as_completed(futures):
                    prog.update(task, advance=1)
                    result = f.result()
                    if result:
                        open_ports.append(result)
        open_ports.sort(key=lambda x: x[0])
    else:
        for i, port in enumerate(ports):
            result = check(port)
            if result: open_ports.append(result)
            print(f"\r  [*] Progresso: {i+1}/{total}", end="")
        print()

    if open_ports:
        if RICH_OK:
            table = Table(title=f"Portas Abertas — {len(open_ports)} encontradas", box=box.ROUNDED, border_style="green")
            table.add_column("Porta", style="cyan", justify="center")
            table.add_column("Servico", style="bold green")
            table.add_column("Versao", style="dim")
            table.add_column("Status", justify="center")
            for port, service, banner in open_ports:
                sensitive = port in [3389, 445, 5985, 5986, 1433, 3306, 6379, 27017]
                status = "[bold yellow]Exposicao Sensivel[/bold yellow]" if sensitive else "[green]Aberta[/green]"
                vers = banner[:50] if banner else "-"
                table.add_row(str(port), service, vers, status)
            cprint(table)
        else:
            print("\n  Portas Abertas:")
            for port, service, banner in open_ports:
                banner_txt = f" | {banner[:50]}" if banner else ""
                print(f"    {port}/TCP  {service}{banner_txt}")
    else:
        step_msg("Nenhuma porta aberta encontrada", "warn")

    return open_ports

def grab_banner(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target, port))
        if port in [80, 8080]:
            s.send(f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: PhantomRecon/2.0\r\nConnection: close\r\n\r\n".encode())
        time.sleep(0.5)
        data = s.recv(1024).decode("utf-8", errors="ignore")
        s.close()
        return data[:200].split("\n")[0].strip()
    except:
        return None

def check_http(target, port=80):
    panel("ANALISE HTTP", f"Requisitando: [bold cyan]{target}:{port}[/bold cyan]")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        s.send(f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: PhantomRecon/2.0\r\nConnection: close\r\n\r\n".encode())
        response = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()

        headers_raw = response.split("\r\n\r\n")[0] if "\r\n\r\n" in response else response
        header_lines = headers_raw.split("\r\n")

        info_lines = [f"Status: [bold]{header_lines[0]}[/bold]"]
        found_headers = {}
        for line in header_lines[1:]:
            for key, label in SECURITY_HEADERS.items():
                if line.lower().startswith(key):
                    val = line.split(":", 1)[1].strip() if ":" in line else ""
                    found_headers[key] = val
                    info_lines.append(f"  [green]{label}[/green]: {val}")

        if not found_headers:
            info_lines.append("  [yellow]Nenhum header de seguranca encontrado[/yellow]")
        else:
            missing = [label for key, label in SECURITY_HEADERS.items() if key not in found_headers]
            if missing:
                info_lines.append(f"\n  [bold red]Faltam: {', '.join(missing)}[/bold red]")

        panel("Headers HTTP", "\n".join(info_lines))
        return response
    except socket.timeout:
        step_msg("Timeout na requisicao HTTP", "err")
    except Exception as e:
        step_msg(f"Erro HTTP: {str(e)}", "err")
    return None

def check_https(target, port=443):
    panel("ANALISE SSL/TLS", f"Conectando: [bold cyan]{target}:{port}[/bold cyan]")
    import ssl as sslmod
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        ctx = sslmod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = sslmod.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=target)
        ss.connect((target, port))
        step_msg("Conexao SSL estabelecida", "ok")

        info = {"ssl": "ativo"}
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert_der = ss.getpeercert(binary_form=True)
            cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
            subject = cert_obj.subject.rfc4514_string()
            issuer = cert_obj.issuer.rfc4514_string()
            exp = cert_obj.not_valid_after
            if exp.tzinfo is not None: exp = exp.replace(tzinfo=None)
            exp_str = exp.strftime("%Y-%m-%d %H:%M:%S")
            valid = exp.replace(tzinfo=None) > datetime.now(UTC).replace(tzinfo=None)
            info.update({"subject": subject, "issuer": issuer, "expires": exp_str, "valid": str(valid)})

            lines = [
                f"  Subject: [bold]{subject}[/bold]",
                f"  Emissor: {issuer}",
                f"  Validade: [{'green' if valid else 'red'}]{exp_str}[/{'green' if valid else 'red'}]",
                f"  Status: [{'green' if valid else 'red'}]{'VALIDO' if valid else 'EXPIRADO'}[/{'green' if valid else 'red'}]"
            ]
            panel("Certificado SSL", "\n".join(lines))
        except ImportError:
            step_msg("Para dados detalhados: pip install cryptography", "warn")
            cert = ss.getpeercert()
            if cert:
                step_msg("Certificado presente e valido", "ok")
                info["status"] = "certificate present"
        ss.close()
        return info
    except Exception as e:
        step_msg(f"Erro SSL: {str(e)}", "err")
        try: s.close()
        except: pass
    return None

def enumerate_dns(target):
    panel("REGISTROS DNS", f"Consultando: [bold cyan]{target}[/bold cyan]")
    found = []
    for rtype in ["A", "MX", "NS", "TXT", "AAAA", "CNAME"]:
        try:
            result = subprocess.run(
                ["nslookup", f"-type={rtype}", target],
                capture_output=True, text=True, timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            lines = [l.strip() for l in result.stdout.split("\n") if l.strip() and target.lower() in l.lower()]
            for line in lines:
                if ":" in line:
                    val = line.split(":", 1)[1].strip()
                    if val and val != target:
                        found.append((rtype, val))
        except:
            pass

    if found:
        if RICH_OK:
            table = Table(title="Registros DNS", box=box.ROUNDED, border_style="blue")
            table.add_column("Tipo", style="cyan", justify="center")
            table.add_column("Valor", style="white")
            for rtype, val in found:
                table.add_row(rtype, val)
            cprint(table)
        else:
            for rtype, val in found:
                print(f"  {rtype}: {val}")
    else:
        step_msg("Nenhum registro DNS adicional encontrado", "warn")

def generate_html_report(target, ips, open_ports, http_data, https_data, filename):
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    port_rows = ""
    for port, service, banner in open_ports:
        sensitive = "class='critical'" if port in [3389, 445, 5985, 5986, 1433, 3306, 6379, 27017] else ""
        versao = f"<br><span style='color:#888;font-size:11px'>{banner[:60]}</span>" if banner else ""
        port_rows += f"<tr><td>{port}</td><td>{service}{versao}</td><td {sensitive}>Exposicao Sensivel</td></tr>"

    http_section = ""
    if http_data:
        safe_http = http_data[:2000].replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
        http_section = f"""
        <div class="section">
            <div class="section-title">🌐 HTTP Headers</div>
            <div class="section-content"><pre>{safe_http}</pre></div>
        </div>"""

    https_section = ""
    if https_data:
        cert_info = ""
        if "subject" in https_data:
            cert_info = f"""
            <div class="info-grid">
                <div class="info-item"><span class="label">Subject</span><span>{https_data['subject']}</span></div>
                <div class="info-item"><span class="label">Emissor</span><span>{https_data['issuer']}</span></div>
                <div class="info-item"><span class="label">Validade</span><span>{https_data['expires']}</span></div>
                <div class="info-item"><span class="label">Status</span><span class="{'valid' if https_data.get('valid')=='True' else 'expired'}">{'VALIDO' if https_data.get('valid')=='True' else 'EXPIRADO'}</span></div>
            </div>"""
        https_section = f"""
        <div class="section">
            <div class="section-title">🔒 SSL/TLS</div>
            <div class="section-content">{cert_info}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhantomRecon — {target}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #0a0a0a; color: #c0c0c0; font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace; padding: 20px; }}
.container {{ max-width: 900px; margin: 0 auto; }}
.header {{ text-align: center; padding: 40px 0; border-bottom: 1px solid #00ff88; margin-bottom: 30px; }}
.header h1 {{ color: #00ff88; font-size: 28px; letter-spacing: 3px; }}
.header .sub {{ color: #666; font-size: 13px; margin-top: 5px; }}
.header .target {{ color: #00ff88; font-size: 18px; margin-top: 10px; }}
.header .date {{ color: #555; font-size: 12px; margin-top: 5px; }}
.section {{ background: #111; border: 1px solid #222; border-radius: 6px; margin-bottom: 20px; overflow: hidden; }}
.section-title {{ background: #1a1a1a; padding: 12px 18px; color: #00ff88; font-weight: bold; font-size: 14px; border-bottom: 1px solid #222; }}
.section-content {{ padding: 15px 18px; font-size: 13px; line-height: 1.6; }}
pre {{ background: #0d0d0d; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 11px; color: #aaa; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ text-align: left; padding: 10px 12px; background: #1a1a1a; color: #00ff88; border-bottom: 1px solid #333; }}
td {{ padding: 8px 12px; border-bottom: 1px solid #1a1a1a; }}
td.critical {{ color: #ff4444; font-weight: bold; }}
.info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
.info-item {{ background: #0d0d0d; padding: 10px 14px; border-radius: 4px; border-left: 3px solid #00ff88; }}
.info-item .label {{ display: block; font-size: 10px; color: #666; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }}
.info-item span {{ font-size: 13px; }}
.valid {{ color: #00ff88; }}
.expired {{ color: #ff4444; }}
.footer {{ text-align: center; padding: 30px 0; color: #444; font-size: 12px; border-top: 1px solid #1a1a1a; margin-top: 30px; }}
.footer a {{ color: #00ff88; text-decoration: none; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>PHANTOMRECON</h1>
        <div class="sub">Pentest Recon Toolkit for Windows</div>
        <div class="target">🎯 {target}</div>
        <div class="date">{now}</div>
    </div>

    <div class="section">
        <div class="section-title">📡 Alvo</div>
        <div class="section-content">
            <div class="info-grid">
                <div class="info-item"><span class="label">Host</span><span>{target}</span></div>
                <div class="info-item"><span class="label">IPs</span><span>{', '.join(ips) if ips else 'N/A'}</span></div>
                <div class="info-item"><span class="label">Portas Abertas</span><span>{len(open_ports)}</span></div>
                <div class="info-item"><span class="label">Operador</span><span>Raphael Lopes</span></div>
            </div>
        </div>
    </div>

    <div class="section">
        <div class="section-title">🔌 Portas Abertas ({len(open_ports)})</div>
        <div class="section-content">
            <table>
                <tr><th>Porta</th><th>Servico</th><th>Status</th></tr>
                {port_rows if port_rows else '<tr><td colspan="3">Nenhuma porta aberta</td></tr>'}
            </table>
        </div>
    </div>

    {http_section}
    {https_section}

    <div class="footer">
        Gerado pelo PhantomRecon v{VERSION} &mdash; <a href="https://github.com/Raphaellopes-dev/phantomrecon" target="_blank">github.com/Raphaellopes-dev/phantomrecon</a>
    </div>
</div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename

def generate_report(target, ips, ports, http_data, https_data):
    Path(OUTPUT_DIR).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r'[^\w.-]', '_', target)

    # TXT
    txt_file = f"{OUTPUT_DIR}/recon_{safe_target}_{ts}.txt"
    with open(txt_file, "w", encoding="utf-8") as f:
        f.write("="*60 + "\n")
        f.write(f"  PHANTOMRECON v{VERSION} - Relatorio de Reconhecimento\n")
        f.write(f"  Alvo: {target}\n")
        f.write(f"  Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write(f"  Operador: Raphael Lopes\n")
        f.write("="*60 + "\n\n")
        f.write(f"  Alvo: {target}\n")
        if ips: f.write(f"  IPs: {', '.join(ips)}\n")
        f.write("\n")
        if ports:
            f.write("-"*50 + "\n")
            f.write("  PORTAS ABERTAS\n")
            f.write("-"*50 + "\n")
            for p, s, banner in ports:
                line = f"    {p}/TCP  {s}"
                if banner: line += f"  |  {banner[:60]}"
                f.write(line + "\n")
            f.write("\n")
        f.write("="*60 + "\n")
        f.write(f"  github.com/Raphaellopes-dev\n")
        f.write("="*60 + "\n")

    # HTML
    html_file = f"{OUTPUT_DIR}/recon_{safe_target}_{ts}.html"
    generate_html_report(target, ips, ports, http_data, https_data, html_file)

    step_msg(f"Relatorio TXT: {txt_file}", "ok")
    step_msg(f"Relatorio HTML: {html_file}", "ok")
    return txt_file, html_file

def run_recon(target, profile="quick"):
    cprint(BANNER)
    step_msg(f"Alvo: [bold green]{target}[/bold green] | Perfil: [bold cyan]{profile}[/bold cyan]", "highlight")
    step_msg(f"Iniciando: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", "info")

    ips = resolve_dns(target)
    if not ips:
        step_msg("Nao foi possivel resolver o alvo. Tentando como IP...", "warn")
        main_ip = target
    else:
        main_ip = ips[0]

    ping_host(main_ip)
    open_ports = scan_ports(main_ip, profile)

    http_data = None
    https_data = None
    for port, service, _ in open_ports:
        if port in (80, 8080): http_data = check_http(target, port)
        if port in (443, 8443): https_data = check_https(target, port)

    if not http_data and not https_data:
        step_msg("Testando HTTP na porta 80...", "info")
        http_data = check_http(target, 80)

    enumerate_dns(target)

    txt_file, html_file = generate_report(target, ips, open_ports, http_data, https_data)

    panel("RESUMO", "\n".join([
        f"  Alvo: [bold green]{target}[/bold green]",
        f"  IPs: {len(ips)}",
        f"  Portas abertas: [{'bold red' if len(open_ports) > 5 else 'green'}]{len(open_ports)}[/{'bold red' if len(open_ports) > 5 else 'green'}]",
        f"  Relatorio TXT: [cyan]{txt_file}[/cyan]",
        f"  Relatorio HTML: [cyan]{html_file}[/cyan]"
    ]))

    cprint("\n[bold green]  Reconhecimento concluido com sucesso![/bold green]")

def interactive():
    cprint(BANNER)
    panel("PhantomRecon v" + VERSION, "[bold green]Modo Interativo[/bold green]\n\nDigite o alvo e escolha o perfil de scan.")
    target = input("\n  [Target] Dominio ou IP: ").strip()
    if not target:
        step_msg("Target invalido", "err")
        return
    print("  [Profile] quick (padrao, 25 portas) | full (1024+ portas)")
    profile = input("  [Profile] (quick): ").strip() or "quick"
    if profile not in ("quick", "full"):
        profile = "quick"
    run_recon(target, profile)

def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
        profile = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] in ("quick", "full") else "quick"
        run_recon(target, profile)
    else:
        interactive()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cprint("\n\n  [!] Operacao cancelada pelo usuario\n", "bold yellow")
        sys.exit(0)
