"""
Módulo: DNS & WHOIS
Cubre: registros DNS (A,MX,NS,TXT,CNAME,SOA), WHOIS, transferencia de zona,
       subdominios comunes, registros SPF/DMARC/DKIM
"""
import socket, subprocess, shutil, re

SUBDOMINIOS_COMUNES = [
    "www","mail","smtp","pop","imap","ftp","vpn","admin","portal","api",
    "dev","staging","test","beta","demo","app","web","blog","shop","login",
    "remote","citrix","owa","autodiscover","webmail","mx","ns1","ns2",
    "m","mobile","static","cdn","media","assets","img","cpanel","whm",
    "secure","dashboard","panel","git","gitlab","jenkins","jira","wiki",
]

def _resolve(host):
    try: return socket.gethostbyname(host)
    except: return None

def _dig(args, timeout=10):
    if not shutil.which("dig"): return ""
    try:
        r = subprocess.run(["dig","+short","+timeout=5"]+args,
                           capture_output=True,text=True,timeout=timeout)
        return r.stdout.strip()
    except: return ""

def _whois(domain):
    if not shutil.which("whois"): return ""
    try:
        r = subprocess.run(["whois",domain],capture_output=True,text=True,timeout=15)
        return r.stdout[:3000]
    except: return ""

def run(target, cb):
    hallazgos = []
    # Extraer dominio limpio
    domain = re.sub(r"https?://","",target).split("/")[0].split(":")[0]
    # Si es IP pura, análisis reducido
    is_ip = re.match(r"^\d+\.\d+\.\d+\.\d+$", domain)

    # ── Resolución básica ─────────────────────────────────────────
    cb("dns","▶ Resolviendo DNS...")
    ip = _resolve(domain)
    if ip:
        hallazgos.append({"modulo":"dns","severidad":"info",
            "titulo":f"IP resuelta: {ip}","descripcion":f"{domain} → {ip}","evidencia":ip})
    else:
        hallazgos.append({"modulo":"dns","severidad":"medio",
            "titulo":"No se pudo resolver el dominio","descripcion":domain,"evidencia":""})
        return hallazgos

    if is_ip:
        # PTR inverso
        ptr = _dig(["-x", domain])
        if ptr:
            hallazgos.append({"modulo":"dns","severidad":"info",
                "titulo":f"PTR (reverso) para {domain}","descripcion":ptr,"evidencia":ptr})
        return hallazgos

    # ── Registros DNS ─────────────────────────────────────────────
    cb("dns","▶ Obteniendo registros DNS (A, MX, NS, TXT, CNAME, SOA)...")
    tipos = ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA"]
    for tipo in tipos:
        out = _dig([domain, tipo])
        if not out: continue
        # Analizar TXT para SPF/DMARC/DKIM
        if tipo == "TXT":
            for linea in out.splitlines():
                low = linea.lower()
                if "v=spf1" in low:
                    sev = "info"
                    if "~all" in low: sev = "bajo"
                    if "+all" in low: sev = "alto"
                    hallazgos.append({"modulo":"dns","severidad":sev,
                        "titulo":"Registro SPF detectado",
                        "descripcion":linea,"evidencia":linea})
                elif "v=dmarc1" in low:
                    sev = "info" if "p=reject" in low else "medio" if "p=quarantine" in low else "alto"
                    hallazgos.append({"modulo":"dns","severidad":sev,
                        "titulo":f"DMARC: política={'reject' if 'p=reject' in low else 'quarantine' if 'p=quarantine' in low else 'none (débil)'}",
                        "descripcion":linea,"evidencia":linea})
                else:
                    hallazgos.append({"modulo":"dns","severidad":"info",
                        "titulo":f"Registro TXT","descripcion":linea,"evidencia":linea})
        elif tipo == "MX":
            for linea in out.splitlines():
                hallazgos.append({"modulo":"dns","severidad":"info",
                    "titulo":f"Servidor de correo (MX)","descripcion":linea,"evidencia":linea})
        elif tipo == "NS":
            for linea in out.splitlines():
                hallazgos.append({"modulo":"dns","severidad":"info",
                    "titulo":f"Nameserver (NS)","descripcion":linea,"evidencia":linea})
        elif tipo == "SOA":
            hallazgos.append({"modulo":"dns","severidad":"info",
                "titulo":"Registro SOA (autoridad de zona)","descripcion":out,"evidencia":out})
        elif tipo in ("A","AAAA"):
            hallazgos.append({"modulo":"dns","severidad":"info",
                "titulo":f"Registro {tipo}","descripcion":out,"evidencia":out})
        elif tipo == "CAA":
            hallazgos.append({"modulo":"dns","severidad":"info",
                "titulo":"Registro CAA (autorización de CA)","descripcion":out,"evidencia":out})

    # ── Transferencia de zona (AXFR) ──────────────────────────────
    cb("dns","▶ Intentando transferencia de zona (AXFR)...")
    ns_raw = _dig([domain,"NS"])
    for ns in (ns_raw.splitlines() if ns_raw else []):
        ns = ns.strip().rstrip(".")
        axfr = _dig([f"@{ns}", domain, "AXFR"])
        if axfr and len(axfr) > 50 and "Transfer failed" not in axfr:
            hallazgos.append({"modulo":"dns","severidad":"critico",
                "titulo":f"¡Transferencia de zona AXFR exitosa desde {ns}!",
                "descripcion":"El servidor DNS permite transferencias completas de zona — expone todos los subdominios.",
                "evidencia":axfr[:500]})
            break

    # ── Subdominios comunes ───────────────────────────────────────
    cb("dns","▶ Comprobando subdominios comunes...")
    encontrados = []
    for sub in SUBDOMINIOS_COMUNES:
        fqdn = f"{sub}.{domain}"
        ip_sub = _resolve(fqdn)
        if ip_sub:
            encontrados.append(f"{fqdn} → {ip_sub}")
    if encontrados:
        sev = "medio" if any("admin" in s or "dev" in s or "test" in s for s in encontrados) else "bajo"
        hallazgos.append({"modulo":"dns","severidad":sev,
            "titulo":f"Subdominios activos encontrados ({len(encontrados)})",
            "descripcion":"\n".join(encontrados),
            "evidencia":"\n".join(encontrados[:10])})

    # ── DKIM (comprobación básica) ────────────────────────────────
    for selector in ["default","google","mail","k1","dkim","s1","s2","smtp"]:
        dkim = _dig([f"{selector}._domainkey.{domain}","TXT"])
        if dkim and "v=DKIM1" in dkim:
            hallazgos.append({"modulo":"dns","severidad":"info",
                "titulo":f"DKIM encontrado (selector: {selector})",
                "descripcion":dkim[:200],"evidencia":selector})
            break

    # ── WHOIS ─────────────────────────────────────────────────────
    cb("dns","▶ Obteniendo información WHOIS...")
    whois_data = _whois(domain)
    if whois_data:
        # Extraer datos clave
        campos = {}
        for linea in whois_data.splitlines():
            for campo in ["Registrar","Creation Date","Updated Date","Expiry Date",
                          "Registrant","Admin","Name Server","DNSSEC"]:
                if linea.strip().lower().startswith(campo.lower()+":"):
                    val = linea.split(":",1)[1].strip()
                    if campo not in campos:
                        campos[campo] = val
        resumen = "\n".join(f"{k}: {v}" for k,v in campos.items())
        hallazgos.append({"modulo":"dns","severidad":"info",
            "titulo":"Información WHOIS del dominio","descripcion":resumen,"evidencia":resumen})

        # DNSSEC
        if "unsigned" in whois_data.lower() or "dnssec: no" in whois_data.lower():
            hallazgos.append({"modulo":"dns","severidad":"bajo",
                "titulo":"DNSSEC no configurado",
                "descripcion":"El dominio no usa DNSSEC — vulnerable a DNS spoofing.",
                "evidencia":"WHOIS: DNSSEC unsigned"})

    cb("dns",f"✔ DNS: {len(hallazgos)} hallazgos")
    return hallazgos
