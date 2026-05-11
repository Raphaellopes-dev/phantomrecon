from config import SENSITIVE_PORTS, SEVERITY, CONFIDENCE

def severity_label(score):
    if score >= 5: return "CRITICAL"
    if score >= 4: return "HIGH"
    if score >= 3: return "MEDIUM"
    if score >= 2: return "LOW"
    return "INFO"

def confidence_label(score):
    if score >= 5: return "CONFIRMED"
    if score >= 4: return "LIKELY"
    if score >= 3: return "SUSPECTED"
    return "LOW_CONFIDENCE"

def port_severity(port):
    return "CRITICAL" if port in SENSITIVE_PORTS else "LOW"

def calculate_security_score(results):
    deductions = []
    score = 100
    ports = results.get("ports", [])
    sensitive_count = sum(1 for p in ports if p[0] in SENSITIVE_PORTS)
    if sensitive_count:
        d = min(sensitive_count * 15, 40)
        score -= d
        deductions.append(f"{sensitive_count} porta(s) sensivel(is): -{d}")
    vulns = results.get("vulnerabilities", [])
    header_count = sum(1 for v in vulns if v.get("type") == "Missing Security Header")
    if header_count:
        d = min(header_count * 10, 40)
        score -= d
        deductions.append(f"{header_count} header(s) ausente(s): -{d}")
    adm = results.get("admin_panels", [])
    if adm:
        d = min(len(adm) * 10, 30)
        score -= d
        deductions.append(f"{len(adm)} painel(is) admin exposto(s): -{d}")
    lfi = results.get("lfi", [])
    lfi_real = [l for l in lfi if len(l) > 2 and l[2] in ("CONFIRMED", "LIKELY")]
    if lfi_real:
        d = min(len(lfi_real) * 25, 50)
        score -= d
        deductions.append(f"{len(lfi_real)} LFI confirmado(s): -{d}")
    creds = results.get("exploits_creds", [])
    if creds:
        score -= 30
        deductions.append("Credenciais padrao validas: -30")
    sqli = results.get("exploits_sqli", [])
    sqli_high = [s for s in sqli if len(s) > 2 and s[2] in ("HIGH", "CONFIRMED", "LIKELY")]
    if sqli_high:
        score -= 30
        deductions.append("SQL Injection detectado: -30")
    cmdi = results.get("exploits_cmd", [])
    cmdi_real = [c for c in cmdi if len(c) > 3 and c[3] in ("CONFIRMED", "LIKELY")]
    if cmdi_real:
        score -= 30
        deductions.append("Command Injection confirmado: -30")
    cves = results.get("cves", [])
    if cves:
        score -= 15 * len(cves)
        deductions.append(f"CVE(s) detectado(s): -{15 * len(cves)}")
    xss = results.get("exploits_xss", [])
    xss_real = [x for x in xss if len(x) > 3 and x[3] in ("CONFIRMED", "LIKELY")]
    if xss_real:
        score -= 25
        deductions.append("XSS confirmado: -25")
    score = max(0, min(100, score))
    grade = "A+" if score >= 90 else "A" if score >= 80 else "B" if score >= 70 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {"score": score, "grade": grade, "deductions": deductions}

def generate_avaliacao_explanation(results):
    target = results.get("target", "desconhecido")
    ips = results.get("ips", [])
    ports = results.get("ports", [])
    vulns = results.get("vulnerabilities", [])
    dirs = results.get("directories", [])
    adm = results.get("admin_panels", [])
    tech = results.get("tech", {})
    lfi = results.get("lfi", [])
    creds = results.get("exploits_creds", [])
    sqli = results.get("exploits_sqli", [])
    cmdi = results.get("exploits_cmd", [])
    cves = results.get("cves", [])
    xss = results.get("exploits_xss", [])
    wp = results.get("wordpress", {})
    apache_cve = results.get("apache_cve", None)
    forms = results.get("forms", [])
    score = results.get("security_score", {})

    lines = []
    lines.append("=== AVALIACAO FINAL ===")
    lines.append("")
    lines.append(f"O site {target} {'(' + ips[0] + ')' if ips else ''} foi analisado pelo PhantomRecon.")
    lines.append("Foram testados: portas abertas, servidores web, crawler de paginas, diretorios,")
    lines.append("paineis admin, headers de seguranca, formularios, e exploracao ativa de")
    lines.append("vulnerabilidades (CVE, LFI, SQLi, XSS, CMDi, credenciais, WordPress).")
    lines.append("")

    if ports:
        lines.append(f"PORTAS ABERTAS: {len(ports)} ponto(s) de entrada no servidor.")
        for p, s, b in ports:
            desc = {22: "(SSH - acesso remoto ao servidor)", 80: "(HTTP - site comum)",
                    443: "(HTTPS - site seguro)", 21: "(FTP - transferencia de arquivos)",
                    3389: "(RDP - area de trabalho remota)", 3306: "(MySQL - banco de dados)",
                    445: "(SMB - compartilhamento de arquivos)", 8080: "(HTTP alternativo)",
                    8443: "(HTTPS alternativo)", 1433: "(MSSQL - banco de dados)",
                    5432: "(PostgreSQL - banco de dados)", 27017: "(MongoDB - banco de dados)",
                    6379: "(Redis - cache/banco)", 5900: "(VNC - acesso remoto grafico)",
                    25: "(SMTP - envio de email)", 110: "(POP3 - recebimento de email)"}.get(p, "")
            banner_str = f" - {b[:60]}" if b else ""
            sens = " [ATENCAO: porta de alto risco!]" if p in SENSITIVE_PORTS else ""
            lines.append(f"  - Porta {p} ({s}){banner_str}{sens} {desc}")
    else:
        lines.append("Nenhuma porta aberta encontrada. O servidor esta bem restrito.")
    lines.append("")

    if cves:
        lines.append("VULNERABILIDADES CONHECIDAS (CVE):")
        for c in cves:
            lines.append(f"  [!] {c.get('cve','?')} - {c.get('desc','')}")
        if apache_cve:
            lines.append("  [!] EXPLOIT FUNCIONAL! Path Traversal confirmado via Apache CVE.")
        lines.append("")

    header_count = sum(1 for v in vulns if v.get("type") == "Missing Security Header")
    if header_count:
        lines.append(f"HEADERS DE SEGURANCA: {header_count} header(s) de protecao estao faltando.")
        lines.append("Isso significa que o site nao esta usando protecoes modernas contra")
        lines.append("ataques comuns como clickjacking, XSS e sequestro de clique.")
    else:
        lines.append("HEADERS DE SEGURANCA: Todos os headers importantes estao presentes. Ponto positivo!")
    lines.append("")

    if tech:
        t_str = ", ".join(f"{k}={v}" for k, v in tech.items())
        lines.append(f"TECNOLOGIAS DETECTADAS: {t_str}")
    if wp:
        for path, info in wp.items():
            if isinstance(info, dict) and info.get("accessible"):
                lines.append(f"  [!] {info.get('label','')} acessivel em {path}")
        wp_users = wp.get("wp_users", [])
        if wp_users:
            lines.append(f"  [!] USUARIOS WORDPRESS EXPOSTOS: {', '.join(wp_users)}")
    if forms:
        lines.append(f"CRAWLER WEB: {len(forms)} formulario(s) encontrado(s) e testados.")
    lines.append("")

    if adm:
        lines.append(f"PAINEIS ADMIN: {len(adm)} painel(is) administrativo(s) encontrado(s)!")
        for a in adm:
            lines.append(f"  - /{a[0]} (acessivel)")
        lines.append("Recomendacao: restrinja o acesso por IP ou use autenticacao de dois fatores.")
    else:
        lines.append("PAINEIS ADMIN: Nenhum painel administrativo publico encontrado. Bom!")
    lines.append("")

    lines.append("TESTES DE PENETRACAO REALIZADOS:")
    lfi_real = [l for l in lfi if len(l) > 2 and l[2] in ("CONFIRMED", "LIKELY")]
    if lfi_real:
        lines.append(f"  [FALHA] LFI (Path Traversal): {len(lfi_real)} vulnerabilidade(s) encontrada(s)!")
        lines.append("    Um invasor pode ler arquivos internos do servidor. Corrigir URGENTE.")
    else:
        lines.append("  [OK] LFI (Path Traversal): Nenhuma falha encontrada.")
    if creds:
        lines.append(f"  [FALHA] CREDENCIAIS PADRAO: {len(creds)} par(es) de login/senha funcionaram!")
        for c in creds:
            lines.append(f"    {c[0]}:{c[1]} — Troque imediatamente!")
    else:
        lines.append("  [OK] CREDENCIAIS PADRAO: Nenhuma combinacao de login/senha comum funcionou.")
    sqli_real = [s for s in sqli if len(s) > 2 and s[2] in ("HIGH", "CONFIRMED", "LIKELY")]
    if sqli_real:
        lines.append(f"  [FALHA] SQL INJECTION: {len(sqli_real)} ponto(s) vulneravel(is)!")
        lines.append("    Um invasor pode manipular consultas ao banco de dados. Corrigir URGENTE.")
    else:
        lines.append("  [OK] SQL INJECTION: Nenhum ponto de injecao de SQL encontrado nos formularios.")
    xss_real = [x for x in xss if len(x) > 3 and x[3] in ("CONFIRMED", "LIKELY")]
    if xss_real:
        lines.append(f"  [FALHA] XSS: {len(xss_real)} ponto(s) vulneravel(is)!")
        lines.append("    Um invasor pode injetar scripts maliciosos no site. Corrigir URGENTE.")
    else:
        lines.append("  [OK] XSS: Nenhum formulario refletiu scripts maliciosos.")
    if apache_cve:
        lines.append(f"  [FALHA] APACHE CVE: Path Traversal funcional via {apache_cve[0]}!")
        lines.append("    Um invasor pode ler arquivos internos do servidor (CVE critico).")
    if cmdi:
        lines.append("  [FALHA] COMMAND INJECTION detectado!")
    else:
        lines.append("  [OK] COMMAND INJECTION: Nenhum comando pode ser executado remotamente.")
    lines.append("")

    if dirs:
        lines.append(f"DIRETORIOS ENCONTRADOS: {len(dirs)} pasta(s) acessivel(is).")
        for d in dirs:
            lines.append(f"  - /{d[0]} ({d[1]})")
    lines.append("")

    s = score.get("score", 0)
    g = score.get("grade", "?")
    if s >= 80:
        lines.append(f"AVALIACAO FINAL: O site {target} esta bem protegido. Score {s}/100 (Grade {g}).")
        lines.append("Parabens! A seguranca esta em dia. Continue monitorando.")
    elif s >= 50:
        lines.append(f"AVALIACAO FINAL: O site {target} possui seguranca MEDIANA. Score {s}/100 (Grade {g}).")
        lines.append("Os principais pontos de atencao sao headers ausentes, portas acessiveis,")
        lines.append("e possiveis configuracoes incorretas. Recomendamos revisar com um profissional.")
    else:
        lines.append(f"AVALIACAO FINAL: O site {target} possui seguranca BAIXA. Score {s}/100 (Grade {g}).")
        lines.append("Foram encontradas vulnerabilidades serias que precisam de correcao imediata.")
        lines.append("Procure um profissional de seguranca digital para resolver os problemas apontados.")
    lines.append("")
    lines.append("Relatorios completos em HTML e PDF foram gerados na pasta 'reports/'.")

    return "\n".join(lines)
