import html as htmlmod
from datetime import datetime
from pathlib import Path
from config import VERSION, EDITION, OUTPUT_DIR, SENSITIVE_PORTS, SEVERITY, CONFIDENCE

def generate_reports(result, html_file, txt_file):
    target = result.get("target", "unknown")
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    ips = ", ".join(result.get("ips", []))
    ports = result.get("ports", [])
    http_h = result.get("http", {})
    ssl_d = result.get("ssl", {})
    dirs = result.get("directories", [])
    adm = result.get("admin_panels", [])
    tech = result.get("tech", {})
    vulns = result.get("vulnerabilities", [])
    dns = result.get("dns", [])
    security_score = result.get("security_score", {})

    port_r = ""
    for p, s, b in ports:
        cls = "critical" if p in SENSITIVE_PORTS else ""
        banner = f"<br><span style='color:#888'>{htmlmod.escape(b[:60])}</span>" if b else ""
        port_r += f"<tr><td>{p}</td><td>{htmlmod.escape(s)}{banner}</td><td class='{cls}'>" + ("Exposicao Sensivel" if cls else "Aberta") + "</td></tr>"

    http_s = ""
    if http_h:
        hdrs = "".join(f'<span class="tag">{htmlmod.escape(k)}</span> ' for k in http_h.get("headers", {}))
        miss = "".join(f'<span class="tag missing">{htmlmod.escape(m)}</span> ' for m in http_h.get("missing", []))
        http_s = f'<div class="card"><div class="card-title">HTTP Headers</div><div class="card-body"><p>Status: <b>{htmlmod.escape(http_h.get("status",""))}</b></p><p>Presentes: {hdrs or "-"}</p><p>Ausentes: {miss or "-"}</p></div></div>'

    ssl_s = ""
    if ssl_d:
        items = "".join(f"<p><b>{k.title()}:</b> {htmlmod.escape(str(v))}</p>" for k, v in ssl_d.items() if k != "ssl")
        ssl_s = f'<div class="card"><div class="card-title">SSL/TLS</div><div class="card-body">{items}</div></div>'

    dir_s = ""
    if dirs:
        dr = "".join(f"<tr><td>/{htmlmod.escape(d[0])}</td><td>{d[1]}</td><td>{d[2]}</td>"
                     f"<td class='conf-{d[3].lower()}'>{d[3]}</td></tr>" for d in dirs)
        dir_s = f'<div class="card"><div class="card-title">Diretorios ({len(dirs)})</div><div class="card-body"><table><tr><th>Caminho</th><th>Status</th><th>Tamanho</th><th>Confianca</th></tr>{dr}</table></div></div>'

    adm_s = ""
    if adm:
        ad = "".join(f"<tr><td>/{htmlmod.escape(a[0])}</td><td>{a[1]}</td>"
                     f"<td class='conf-{a[2].lower()}'>{a[2]}</td></tr>" for a in adm)
        adm_s = f'<div class="card"><div class="card-title">Paineis Admin ({len(adm)})</div><div class="card-body"><table><tr><th>Caminho</th><th>Status</th><th>Confianca</th></tr>{ad}</table></div></div>'

    tech_s = ""
    if tech:
        tc = "".join(f"<tr><td>{htmlmod.escape(k)}</td><td>{htmlmod.escape(str(v))}</td></tr>" for k, v in tech.items())
        tech_s = f'<div class="card"><div class="card-title">Tecnologias</div><div class="card-body"><table><tr><th>Chave</th><th>Valor</th></tr>{tc}</table></div></div>'

    vuln_s = ""
    if vulns:
        vl = "".join(
            f"<tr><td>{htmlmod.escape(v['type'])}</td><td>{htmlmod.escape(v['target'][:60])}</td>"
            f"<td class='conf-{v.get('confidence','LOW_CONFIDENCE').lower()}'>{v.get('confidence','?')}</td>"
            f"<td><span class='sev-{v.get('severity','info').lower()}'>{v.get('severity','INFO')}</span></td></tr>"
            for v in vulns
        )
        vuln_s = f'<div class="card"><div class="card-title" style="border-left-color:#ff4444">Vulnerabilidades ({len(vulns)})</div><div class="card-body"><table><tr><th>Tipo</th><th>Alvo</th><th>Confianca</th><th>Severidade</th></tr>{vl}</table></div></div>'

    dns_s = ""
    if dns:
        dn = "".join(f"<tr><td>{htmlmod.escape(d['type'])}</td><td>{htmlmod.escape(d['value'])}</td></tr>" for d in dns)
        dns_s = f'<div class="card"><div class="card-title">DNS</div><div class="card-body"><table><tr><th>Tipo</th><th>Valor</th></tr>{dn}</table></div></div>'

    score_s = ""
    if security_score:
        s = security_score["score"]
        g = security_score["grade"]
        color = "#00ff88" if s >= 70 else "#ffaa00" if s >= 40 else "#ff4444"
        deductions_html = ""
        if security_score.get("deductions"):
            deductions_html = ("<p style='margin-top:8px;color:#888'>Deducoes:</p><ul style='color:#ff4444;font-size:11px;list-style:none;padding:0'>"
                               + "".join(f"<li>- {htmlmod.escape(d)}</li>" for d in security_score["deductions"]) + "</ul>")
        score_s = (f'<div class="card"><div class="card-title">Security Score</div><div class="card-body" style="text-align:center;padding:20px">'
                   f'<span style="font-size:48px;font-weight:bold;color:{color}">{s}</span><span style="color:#666;font-size:16px">/100</span><br>'
                   f'<span style="font-size:22px;color:{color};font-weight:bold">Grade: {g}</span>{deductions_html}</div></div>')

    cves = result.get("cves", [])
    cve_s = ""
    if cves:
        cr = "".join(
            f"<tr><td>{htmlmod.escape(c.get('cve','?'))}</td><td>{htmlmod.escape(c.get('desc','')[:80])}</td>"
            f"<td>{htmlmod.escape(c.get('service','?'))} {htmlmod.escape(c.get('version','?'))}</td>"
            f"<td class='conf-confirmed'>" + ("EXPLOIT FUNCIONAL" if result.get('apache_cve') else "Detectado") + "</td></tr>"
            for c in cves
        )
        cve_s = f'<div class="card"><div class="card-title" style="border-left-color:#ff4444">CVE Detectados ({len(cves)})</div><div class="card-body"><table><tr><th>CVE</th><th>Descricao</th><th>Servico</th><th>Status</th></tr>{cr}</table></div></div>'

    wp = result.get("wordpress", {})
    wp_s = ""
    if wp:
        wr = "".join(
            f"<tr><td>{htmlmod.escape(k)}</td><td>{v.get('label','')}</td><td>{v.get('status','')}</td></tr>"
            for k, v in wp.items() if isinstance(v, dict)
        )
        wp_users = wp.get("wp_users", [])
        if wp_users:
            wr += f"<tr><td>Usuarios WordPress</td><td colspan='2'>{htmlmod.escape(', '.join(wp_users))}</td></tr>"
        wp_s = f'<div class="card"><div class="card-title" style="border-left-color:#ff8844">WordPress Findings</div><div class="card-body"><table><tr><th>Endpoint</th><th>Label</th><th>Status</th></tr>{wr}</table></div></div>'

    fp = result.get("fingerprint", {})
    fp_s = ""
    if fp:
        fp_items = []
        if fp.get("cms"):
            fp_items.append(f"CMS: {fp['cms']}")
        if fp.get("cms_server"):
            fp_items.append(f"Servidor: {fp['cms_server']}")
        if fp.get("waf"):
            fp_items.append(f"WAF: {fp['waf']}")
        if fp_items:
            fp_s = f'<div class="card"><div class="card-title">Fingerprinting</div><div class="card-body">{" | ".join(fp_items)}</div></div>'

    aval_t = result.get("avaliacao", "")
    aval_s = ""
    if aval_t:
        aval_html = htmlmod.escape(aval_t).replace("\n", "<br>")
        aval_s = f'<div class="card"><div class="card-title" style="border-left-color:#00ff88">Avaliacao Final</div><div class="card-body" style="font-size:11px;color:#aaa;line-height:1.7">{aval_html}</div></div>'

    html = f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PhantomRecon - {htmlmod.escape(target)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#000;color:#c0c0c0;font-family:'Consolas','Courier New',monospace;padding:30px}}
.container{{max-width:1000px;margin:0 auto}}
.header{{text-align:center;padding:30px 0;border-bottom:1px solid #00ff88;margin-bottom:25px}}
.header h1{{color:#00ff88;font-size:30px;letter-spacing:5px;text-shadow:0 0 20px rgba(0,255,136,.3)}}
.header .target{{color:#00ff88;font-size:16px;margin-top:8px}}
.header .date{{color:#444;font-size:11px;margin-top:4px}}
.card{{background:#0a0a0a;border:1px solid #1a1a1a;border-radius:6px;margin-bottom:16px;overflow:hidden}}
.card-title{{background:#0d0d0d;padding:10px 16px;color:#00ff88;font-weight:bold;font-size:13px;border-left:3px solid #00ff88;border-bottom:1px solid #1a1a1a}}
.card-body{{padding:12px 16px;font-size:12px;line-height:1.8}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{text-align:left;padding:7px 10px;color:#00ff88;border-bottom:1px solid #222}}
td{{padding:6px 10px;border-bottom:1px solid #111}}
td.critical{{color:#ff4444;font-weight:bold}}
.conf-confirmed{{color:#ff4444;font-weight:bold}}
.conf-high{{color:#ff8844}}
.conf-medium{{color:#ffaa00}}
.conf-low{{color:#888}}
.sev-critical{{color:#ff4444;font-weight:bold}}
.sev-high{{color:#ff8844;font-weight:bold}}
.sev-medium{{color:#ffaa00}}
.sev-low{{color:#888}}
.sev-info{{color:#555}}
.tag{{display:inline-block;background:#0a1a0f;color:#00ff88;padding:1px 6px;border-radius:2px;font-size:11px;margin:1px}}
.tag.missing{{background:#1a0a0a;color:#ff4444}}
.footer{{text-align:center;padding:25px;color:#333;font-size:11px;border-top:1px solid #111;margin-top:20px}}
a{{color:#00ff88;text-decoration:none}}
b{{color:#00ff88}}
</style></head>
<body><div class="container">
<div class="header"><h1>PHANTOMRECON <span style="color:#4488ff;font-size:14px">Free Edition</span></h1><div class="target">{htmlmod.escape(target)}</div><div class="date">{now} — v{VERSION}</div></div>
<div class="card"><div class="card-title">Alvo</div><div class="card-body"><p><b>Host:</b> {htmlmod.escape(target)}</p><p><b>IPs:</b> {htmlmod.escape(ips) or "N/A"}</p><p><b>Portas:</b> {len(ports)} | <b>Diretorios:</b> {len(dirs)} | <b>Vulns:</b> {len(vulns)}</p></div></div>
{score_s}
{aval_s}
{('<div class="card"><div class="card-title">Portas Abertas ('+str(len(ports))+')</div><div class="card-body"><table><tr><th>Porta</th><th>Servico</th><th>Status</th></tr>'+port_r+'</table></div></div>') if ports else ''}
{cve_s}{wp_s}{http_s}{ssl_s}{dns_s}{dir_s}{adm_s}{tech_s}{fp_s}{vuln_s}
<div class="footer">PhantomRecon v{VERSION} Free Edition — <a href="https://github.com/Raphaellopes-dev/phantomrecon" target="_blank">github.com/Raphaellopes-dev/phantomrecon</a></div>
</div></body></html>"""

    score_txt = ""
    if security_score:
        score_txt = f"\nSECURITY SCORE: {security_score.get('score', '?')}/100 (Grade: {security_score.get('grade', '?')})"
        if security_score.get("deductions"):
            score_txt += "\n" + "\n".join(f"  - {d}" for d in security_score["deductions"])
        score_txt += "\n\n"

    txt = f"PHANTOMRECON v{VERSION} Free Edition\n{'='*50}\nAlvo: {target}\nData: {now}\n{'='*50}\n\nIPs: {ips or 'N/A'}\n\n{score_txt}"
    if ports:
        txt += "PORTAS ABERTAS:\n" + "-"*40 + "\n"
        for p, s, b in ports:
            txt += f"  {p}/TCP  {s}" + (f"  |  {b[:60]}" if b else "") + "\n"
    if dirs:
        txt += f"\nDIRETORIOS ({len(dirs)}):\n" + "\n".join(f"  /{d[0]} ({d[1]})" for d in dirs) + "\n"
    if adm:
        txt += f"\nPAINEIS ADMIN ({len(adm)}):\n" + "\n".join(f"  /{a[0]} ({a[1]})" for a in adm) + "\n"
    if vulns:
        txt += f"\nVULNERABILIDADES ({len(vulns)}):\n" + "\n".join(f"  [{v['type']}] {v['target'][:60]}" for v in vulns) + "\n"
    txt += f"\n{'='*50}\ngithub.com/Raphaellopes-dev\n{'='*50}\n"

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html)
    with open(txt_file, "w", encoding="utf-8") as f:
        f.write(txt)
