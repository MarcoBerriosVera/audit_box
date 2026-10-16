"""
Módulo: Red
Herramientas: nmap
Cubre: puertos, servicios, versiones, OS, scripts básicos de vuln
"""
import subprocess, shutil, xml.etree.ElementTree as ET, re

PUERTOS_RIESGO = {
    "21":"FTP sin cifrar","23":"Telnet sin cifrar","25":"SMTP expuesto",
    "53":"DNS expuesto","69":"TFTP","110":"POP3 sin cifrar",
    "135":"RPC Windows","139":"NetBIOS","143":"IMAP sin cifrar",
    "445":"SMB (riesgo WannaCry)","512":"rexec","513":"rlogin",
    "514":"rsh","1433":"MSSQL expuesto","1521":"Oracle DB expuesto",
    "3306":"MySQL expuesto","3389":"RDP expuesto","5432":"PostgreSQL expuesto",
    "5900":"VNC expuesto","6379":"Redis sin auth","27017":"MongoDB sin auth",
}

def run(target, cb):
    cb("red","▶ nmap: detectando puertos, servicios y SO...")
    if not shutil.which("nmap"):
        return [{"modulo":"red","severidad":"info","titulo":"nmap no instalado",
                 "descripcion":"apt install nmap","evidencia":""}]

    proc = subprocess.run(
        ["nmap","-sV","-sC","-O","--script=banner,vuln","--open","-oX","-",target],
        capture_output=True, text=True, timeout=300
    )
    hallazgos = []
    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        return [{"modulo":"red","severidad":"info","titulo":"Error parseando nmap",
                 "descripcion":proc.stderr[:200],"evidencia":""}]

    for host in root.findall("host"):
        # OS
        os_el = host.find(".//osmatch")
        if os_el is not None:
            hallazgos.append({"modulo":"red","severidad":"info",
                "titulo":f"SO detectado: {os_el.get('name','')}",
                "descripcion":f"Precisión: {os_el.get('accuracy','?')}%","evidencia":""})

        # Puertos
        for port in host.findall(".//port"):
            st = port.find("state")
            if st is None or st.get("state") != "open": continue
            pid   = port.get("portid","?")
            proto = port.get("protocol","tcp")
            svc   = port.find("service")
            sname = svc.get("name","unknown") if svc is not None else "unknown"
            sprod = svc.get("product","")    if svc is not None else ""
            sver  = svc.get("version","")   if svc is not None else ""
            ver   = f"{sprod} {sver}".strip() or "desconocida"

            nota  = PUERTOS_RIESGO.get(pid,"")
            sev   = "alto" if nota else "bajo"
            desc  = nota if nota else f"Servicio: {sname}, versión: {ver}"
            hallazgos.append({"modulo":"red","severidad":sev,
                "titulo":f"Puerto {pid}/{proto} abierto ({sname})",
                "descripcion":desc,"evidencia":f"versión: {ver}"})

            # Scripts de vuln
            for script in port.findall("script"):
                out = script.get("output","")
                if len(out) < 10: continue
                cves = re.findall(r"CVE-\d{4}-\d+", out, re.I)
                if any(w in out.lower() for w in ["vulnerable","exploitable","VULNERABLE"]):
                    hallazgos.append({"modulo":"red","severidad":"critico" if cves else "alto",
                        "titulo":f"Vuln detectada en puerto {pid}: {script.get('id','')}",
                        "descripcion":out[:400],
                        "evidencia":", ".join(cves) if cves else script.get("id","")})

    cb("red",f"✔ Red: {len(hallazgos)} hallazgos")
    return hallazgos
