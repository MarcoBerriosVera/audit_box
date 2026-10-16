"""
Módulo: Web
Cubre: headers HTTP, SSL/TLS, rutas sensibles, cookies, robots.txt,
       tecnologías (whatweb/nikto), redirecciones, métodos HTTP
"""
import ssl, socket, subprocess, shutil, json, re, urllib.request, urllib.error
from datetime import datetime

HEADERS_SEGURIDAD = {
    "Strict-Transport-Security": ("alto","HSTS no configurado — conexiones HTTP no redirigen a HTTPS"),
    "X-Frame-Options":           ("medio","Clickjacking posible — falta X-Frame-Options"),
    "X-Content-Type-Options":    ("medio","MIME sniffing activo — falta X-Content-Type-Options"),
    "Content-Security-Policy":   ("medio","Sin CSP — XSS más fácil de explotar"),
    "Referrer-Policy":           ("bajo", "Sin Referrer-Policy — puede filtrar URLs internas"),
    "Permissions-Policy":        ("bajo", "Sin Permissions-Policy — acceso sin restricción a APIs del navegador"),
}

RUTAS_SENSIBLES = [
    "/.git/HEAD","/.env","/.htaccess","/.htpasswd","/wp-config.php",
    "/config.php","/admin","/administrator","/phpmyadmin","/adminer.php",
    "/backup.zip","/backup.sql","/db.sql","/database.sql",
    "/robots.txt","/sitemap.xml","/.DS_Store","/server-status",
    "/web.config","/crossdomain.xml","/clientaccesspolicy.xml",
    "/api/swagger.json","/api/openapi.json","/.well-known/security.txt",
    "/phpinfo.php","/info.php","/test.php","/xmlrpc.php",
    "/wp-login.php","/wp-admin","/.svn/entries","/Makefile",
]

def _fetch(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent":"audit_box/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(4096).decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        return e.code, {}, ""
    except Exception:
        return None, {}, ""

def _base_url(target):
    if target.startswith("http"): return target.rstrip("/")
    return f"http://{target}"

def run(target, cb):
    hallazgos = []
    base = _base_url(target)
    host = re.sub(r"https?://","",base).split("/")[0].split(":")[0]

    # ── Headers HTTP ──────────────────────────────────────────────
    cb("web","▶ Analizando headers HTTP...")
    code, headers, body = _fetch(base)
    if code:
        # Headers de seguridad faltantes
        h_lower = {k.lower():v for k,v in headers.items()}
        for h, (sev, msg) in HEADERS_SEGURIDAD.items():
            if h.lower() not in h_lower:
                hallazgos.append({"modulo":"web","severidad":sev,
                    "titulo":f"Header faltante: {h}","descripcion":msg,"evidencia":""})

        # Headers que revelan info
        for h in ["Server","X-Powered-By","X-AspNet-Version","X-Generator"]:
            if h.lower() in h_lower:
                hallazgos.append({"modulo":"web","severidad":"bajo",
                    "titulo":f"Header revela tecnología: {h}",
                    "descripcion":f"Valor: {h_lower[h.lower()]}",
                    "evidencia":h_lower[h.lower()]})

        # Cookies sin flags
        for h,v in headers.items():
            if h.lower() == "set-cookie":
                flags = v.lower()
                if "httponly" not in flags:
                    hallazgos.append({"modulo":"web","severidad":"medio",
                        "titulo":"Cookie sin HttpOnly","descripcion":v[:120],"evidencia":v[:120]})
                if "secure" not in flags and base.startswith("https"):
                    hallazgos.append({"modulo":"web","severidad":"medio",
                        "titulo":"Cookie sin flag Secure en HTTPS","descripcion":v[:120],"evidencia":""})
                if "samesite" not in flags:
                    hallazgos.append({"modulo":"web","severidad":"bajo",
                        "titulo":"Cookie sin SameSite","descripcion":v[:120],"evidencia":""})

        # HTTP expuesto (no redirige a HTTPS)
        if base.startswith("http://"):
            https_code, _, _ = _fetch(f"https://{host}")
            if https_code and https_code < 400:
                hallazgos.append({"modulo":"web","severidad":"medio",
                    "titulo":"Sitio disponible en HTTP sin cifrar",
                    "descripcion":"El servidor responde en HTTP. Si existe HTTPS, debería redirigir.",
                    "evidencia":f"HTTP {code}"})

    # ── SSL/TLS ───────────────────────────────────────────────────
    cb("web","▶ Revisando certificado SSL/TLS...")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(8)
            s.connect((host, 443))
            cert = s.getpeercert()

        # Expiración
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days = (exp - datetime.utcnow()).days
        sev_exp = "critico" if days < 0 else "alto" if days < 15 else "medio" if days < 30 else "info"
        hallazgos.append({"modulo":"web","severidad":sev_exp,
            "titulo":f"Certificado SSL {'EXPIRADO' if days<0 else f'expira en {days} días'}",
            "descripcion":f"Válido hasta: {cert['notAfter']}",
            "evidencia":cert.get("subject","")})

        # Emisor y dominio
        subject = dict(x[0] for x in cert.get("subject",[]))
        issuer  = dict(x[0] for x in cert.get("issuer",[]))
        hallazgos.append({"modulo":"web","severidad":"info",
            "titulo":f"Certificado SSL emitido para: {subject.get('commonName','')}",
            "descripcion":f"Emisor: {issuer.get('organizationName','?')}",
            "evidencia":str(cert.get("subjectAltName",""))[:200]})

        # SANs (Subject Alternative Names)
        sans = [v for t,v in cert.get("subjectAltName",[]) if t=="DNS"]
        if sans:
            hallazgos.append({"modulo":"web","severidad":"info",
                "titulo":f"Dominios en el certificado ({len(sans)} SANs)",
                "descripcion":"Dominios cubiertos por este certificado.",
                "evidencia":", ".join(sans[:20])})

    except ssl.SSLCertVerificationError as e:
        hallazgos.append({"modulo":"web","severidad":"alto",
            "titulo":"Certificado SSL inválido o autofirmado",
            "descripcion":str(e),"evidencia":""})
    except Exception:
        hallazgos.append({"modulo":"web","severidad":"info",
            "titulo":"Sin HTTPS o SSL no accesible","descripcion":"Puerto 443 no respondió.","evidencia":""})

    # ── Rutas sensibles ───────────────────────────────────────────
    cb("web","▶ Buscando rutas y archivos sensibles...")
    for ruta in RUTAS_SENSIBLES:
        url = base + ruta
        code2, _, body2 = _fetch(url, timeout=5)
        if code2 and code2 < 400:
            sev = "critico" if any(w in ruta for w in [".env","config","password","backup",".sql","phpinfo"]) \
                  else "alto" if any(w in ruta for w in [".git","htpasswd","wp-config","admin"]) \
                  else "medio"
            hallazgos.append({"modulo":"web","severidad":sev,
                "titulo":f"Ruta sensible accesible: {ruta}",
                "descripcion":f"HTTP {code2} — {len(body2)} bytes de respuesta",
                "evidencia":body2[:200] if body2 else f"HTTP {code2}"})

    # ── robots.txt ────────────────────────────────────────────────
    code3, _, rbody = _fetch(base + "/robots.txt", timeout=5)
    if code3 and code3 < 400 and rbody:
        disallowed = [l.split(":",1)[1].strip() for l in rbody.splitlines()
                      if l.lower().startswith("disallow:")]
        if disallowed:
            hallazgos.append({"modulo":"web","severidad":"info",
                "titulo":f"robots.txt revela {len(disallowed)} rutas restringidas",
                "descripcion":"Rutas que los bots no deben indexar — pueden ser sensibles.",
                "evidencia":"\n".join(disallowed[:15])})

    # ── Métodos HTTP peligrosos ───────────────────────────────────
    try:
        import http.client
        conn = http.client.HTTPConnection(host, timeout=6)
        conn.request("OPTIONS", "/")
        resp = conn.getresponse()
        allow = resp.getheader("Allow","")
        if any(m in allow for m in ["PUT","DELETE","TRACE","CONNECT"]):
            hallazgos.append({"modulo":"web","severidad":"medio",
                "titulo":"Métodos HTTP peligrosos habilitados",
                "descripcion":f"El servidor permite: {allow}",
                "evidencia":allow})
    except Exception:
        pass

    # ── whatweb ───────────────────────────────────────────────────
    if shutil.which("whatweb"):
        cb("web","▶ Detectando tecnologías con whatweb...")
        proc = subprocess.run(["whatweb","--log-json=-",base],
                              capture_output=True,text=True,timeout=30)
        for linea in proc.stdout.splitlines():
            try:
                d = json.loads(linea)
                techs = []
                for nombre, info in d.get("plugins",{}).items():
                    ver = info.get("version",[])
                    techs.append(f"{nombre}" + (f" {ver[0]}" if ver else ""))
                if techs:
                    hallazgos.append({"modulo":"web","severidad":"info",
                        "titulo":"Tecnologías detectadas","descripcion":", ".join(techs[:25]),
                        "evidencia":", ".join(techs[:25])})
            except Exception:
                pass

    # ── nikto ─────────────────────────────────────────────────────
    if shutil.which("nikto"):
        cb("web","▶ Escaneando vulnerabilidades web con nikto...")
        proc = subprocess.run(["nikto","-h",base,"-nointeractive","-Format","txt"],
                              capture_output=True,text=True,timeout=240)
        for linea in proc.stdout.splitlines():
            linea = linea.strip().lstrip("+ ")
            if not linea or len(linea) < 20: continue
            low = linea.lower()
            sev = ("critico" if any(w in low for w in ["rce","sqli","xss injection"]) else
                   "alto"    if any(w in low for w in ["vuln","outdated","inject"]) else
                   "medio"   if any(w in low for w in ["header","cookie","cors"]) else "info")
            hallazgos.append({"modulo":"web","severidad":sev,
                "titulo":linea[:80],"descripcion":linea,"evidencia":""})

    cb("web",f"✔ Web: {len(hallazgos)} hallazgos")
    return hallazgos
