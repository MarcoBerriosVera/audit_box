"""
Módulo: Metadatos
Cubre: imágenes (EXIF/GPS), documentos PDF/Office/LibreOffice,
       ejecutables PE/ELF, hashes, tipo de archivo, strings
"""
import os, hashlib, struct, re, subprocess, shutil, json
from pathlib import Path

# ── Tipos de archivo por magic bytes ─────────────────────────────
MAGIC = {
    b"\x4d\x5a":               "Windows PE Executable",
    b"\x7fELF":                "Linux ELF Executable",
    b"\xff\xd8\xff":           "JPEG Image",
    b"\x89PNG":                "PNG Image",
    b"\x47\x49\x46":           "GIF Image",
    b"\x25\x50\x44\x46":       "PDF Document",
    b"PK\x03\x04":             "ZIP/Office/APK Archive",
    b"\xd0\xcf\x11\xe0":       "MS Office 97-2003 (OLE)",
    b"\x1f\x8b":               "Gzip Archive",
    b"BZh":                    "Bzip2 Archive",
    b"\x52\x61\x72\x21":       "RAR Archive",
    b"7z\xbc\xaf\x27\x1c":    "7-Zip Archive",
    b"<!DOCTYPE":              "HTML Document",
    b"<html":                  "HTML Document",
    b"#!/":                    "Shell Script",
    b"\xca\xfe\xba\xbe":       "Java Class / Mach-O Fat",
}

def _magic_type(path):
    try:
        with open(path,"rb") as f:
            hdr = f.read(8)
        for sig, name in MAGIC.items():
            if hdr[:len(sig)] == sig:
                return name
    except: pass
    return Path(path).suffix.upper().lstrip(".") or "Desconocido"

def _hashes(path):
    md5 = hashlib.md5()
    sha1= hashlib.sha1()
    sha256=hashlib.sha256()
    try:
        with open(path,"rb") as f:
            for chunk in iter(lambda:f.read(8192),b""):
                md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    except: return "error","error","error"

def _exif_imagen(path):
    """Extrae EXIF con exiftool si disponible, si no con Pillow."""
    hallazgos = []
    if shutil.which("exiftool"):
        r = subprocess.run(["exiftool","-j","-n",str(path)],
                           capture_output=True,text=True,timeout=15)
        try:
            data = json.loads(r.stdout)[0]
            # GPS
            lat = data.get("GPSLatitude"); lon = data.get("GPSLongitude")
            if lat and lon:
                hallazgos.append({"severidad":"alto",
                    "titulo":f"GPS en imagen: lat={lat}, lon={lon}",
                    "descripcion":"La imagen tiene coordenadas GPS — revela ubicación del autor.",
                    "evidencia":f"https://maps.google.com/?q={lat},{lon}"})
            # Cámara y software
            for k in ["Make","Model","Software","CreatorTool"]:
                if v := data.get(k):
                    hallazgos.append({"severidad":"bajo","titulo":f"EXIF: {k}",
                        "descripcion":str(v),"evidencia":str(v)})
            # Fechas
            for k in ["DateTimeOriginal","CreateDate","ModifyDate"]:
                if v := data.get(k):
                    hallazgos.append({"severidad":"info","titulo":f"EXIF fecha: {k}",
                        "descripcion":str(v),"evidencia":str(v)})
            # Autor/copyright
            for k in ["Artist","Author","Creator","Copyright","XPAuthor"]:
                if v := data.get(k):
                    hallazgos.append({"severidad":"medio","titulo":f"EXIF autor: {k}",
                        "descripcion":str(v),"evidencia":str(v)})
        except: pass
    else:
        try:
            from PIL import Image, ExifTags
            img = Image.open(path)
            exif = img._getexif() or {}
            for tag_id, val in exif.items():
                tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                hallazgos.append({"severidad":"info","titulo":f"EXIF: {tag}",
                    "descripcion":str(val)[:200],"evidencia":str(val)[:100]})
        except: pass
    return hallazgos

def _meta_pdf(path):
    hallazgos = []
    if shutil.which("exiftool"):
        r = subprocess.run(["exiftool","-j",str(path)],capture_output=True,text=True,timeout=10)
        try:
            data = json.loads(r.stdout)[0]
            for k in ["Author","Creator","Producer","Title","Subject","Keywords",
                      "CreateDate","ModifyDate","PDFVersion"]:
                if v := data.get(k):
                    sev = "medio" if k in ("Author","Creator") else "info"
                    hallazgos.append({"severidad":sev,"titulo":f"PDF metadata: {k}",
                        "descripcion":str(v),"evidencia":str(v)})
        except: pass
    else:
        try:
            import pypdf
            reader = pypdf.PdfReader(str(path))
            info = reader.metadata or {}
            for k,v in info.items():
                sev = "medio" if "Author" in k or "Creator" in k else "info"
                hallazgos.append({"severidad":sev,"titulo":f"PDF metadata: {k}",
                    "descripcion":str(v),"evidencia":str(v)})
        except: pass
    return hallazgos

def _meta_office(path):
    hallazgos = []
    if shutil.which("exiftool"):
        r = subprocess.run(["exiftool","-j",str(path)],capture_output=True,text=True,timeout=10)
        try:
            data = json.loads(r.stdout)[0]
            campos = ["Author","LastModifiedBy","Creator","Manager","Company",
                      "Title","Subject","CreateDate","ModifyDate","RevisionNumber",
                      "TotalEditTime","AppVersion"]
            for k in campos:
                if v := data.get(k):
                    sev = "medio" if k in ("Author","LastModifiedBy","Company","Manager") else "info"
                    hallazgos.append({"severidad":sev,"titulo":f"Office metadata: {k}",
                        "descripcion":str(v),"evidencia":str(v)})
        except: pass
    return hallazgos

def _analizar_exe(path):
    hallazgos = []
    tipo = _magic_type(path)

    # Strings imprimibles (>= 6 chars)
    try:
        if shutil.which("strings"):
            r = subprocess.run(["strings","-n","6",str(path)],
                               capture_output=True,text=True,timeout=15)
            all_strings = r.stdout.splitlines()
        else:
            with open(path,"rb") as f:
                raw = f.read(1024*512)
            all_strings = re.findall(rb'[ -~]{6,}', raw)
            all_strings = [s.decode("ascii","replace") for s in all_strings]

        # Patrones interesantes en strings
        patterns = {
            r"https?://[^\s\"'<>]+":                          ("info","URL encontrada en strings"),
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b":                  ("info","IP encontrada en strings"),
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]+": ("medio","Email en strings"),
            r"(?i)(password|passwd|pwd|secret|token|apikey|api_key)\s*[=:]\s*\S+": ("alto","Credencial potencial en strings"),
            r"(?i)(admin|root|superuser)":                     ("bajo","Referencia a usuario privilegiado"),
            r"cmd\.exe|powershell|/bin/sh|/bin/bash":         ("alto","Shell reference en strings"),
            r"(?i)(dropper|payload|shellcode|exploit|backdoor)": ("critico","Strings sospechosas de malware"),
        }
        encontrados_strings = []
        for pat, (sev, titulo) in patterns.items():
            matches = list(set(re.findall(pat, "\n".join(all_strings))))
            if matches:
                hallazgos.append({"severidad":sev,"titulo":titulo,
                    "descripcion":"\n".join(matches[:10]),
                    "evidencia":matches[0][:100]})

        hallazgos.append({"severidad":"info","titulo":f"Strings extraídas: {len(all_strings)} cadenas",
            "descripcion":f"Total de strings imprimibles (≥6 chars): {len(all_strings)}",
            "evidencia":"\n".join(all_strings[:5])})
    except Exception as e:
        hallazgos.append({"severidad":"info","titulo":"Error extrayendo strings","descripcion":str(e),"evidencia":""})

    # PE Header (Windows)
    if "PE" in tipo:
        try:
            with open(path,"rb") as f:
                data = f.read(1024)
            # Offset a PE header
            pe_off = struct.unpack_from("<I", data, 0x3c)[0]
            if pe_off < len(data)-4:
                machine = struct.unpack_from("<H", data, pe_off+4)[0]
                arch = {0x014c:"x86 (32-bit)", 0x8664:"x64 (64-bit)",
                        0x01c0:"ARM", 0xaa64:"ARM64"}.get(machine, f"0x{machine:04x}")
                hallazgos.append({"severidad":"info","titulo":f"Arquitectura PE: {arch}",
                    "descripcion":f"Machine type: 0x{machine:04x}","evidencia":arch})
        except: pass

    # VirusTotal hash lookup (solo info — sin API key)
    md5, sha1, sha256 = _hashes(path)
    hallazgos.append({"severidad":"info",
        "titulo":"Hashes del ejecutable (verificar en VirusTotal)",
        "descripcion":f"MD5: {md5}\nSHA1: {sha1}\nSHA256: {sha256}",
        "evidencia":f"https://www.virustotal.com/gui/file/{sha256}"})

    return hallazgos

def analizar_archivo(path, cb=None):
    """Analiza un único archivo y devuelve hallazgos."""
    path = Path(path)
    if not path.exists():
        return [{"modulo":"meta","severidad":"info","titulo":"Archivo no encontrado",
                 "descripcion":str(path),"evidencia":""}]

    hallazgos = []
    tipo = _magic_type(path)
    size = path.stat().st_size
    md5, sha1, sha256 = _hashes(path)

    # Info base
    hallazgos.append({"modulo":"meta","severidad":"info",
        "titulo":f"Archivo: {path.name}",
        "descripcion":f"Tipo: {tipo} | Tamaño: {size:,} bytes\nMD5: {md5}\nSHA256: {sha256}",
        "evidencia":str(path)})

    ext = path.suffix.lower()

    if tipo in ("JPEG Image","PNG Image","GIF Image") or ext in (".jpg",".jpeg",".png",".gif",".tiff",".webp",".heic"):
        if cb: cb("meta",f"  → EXIF imagen: {path.name}")
        for h in _exif_imagen(path):
            h["modulo"]="meta"; hallazgos.append(h)

    elif tipo == "PDF Document" or ext == ".pdf":
        if cb: cb("meta",f"  → Metadatos PDF: {path.name}")
        for h in _meta_pdf(path):
            h["modulo"]="meta"; hallazgos.append(h)

    elif ext in (".docx",".xlsx",".pptx",".odt",".ods",".odp") or tipo in ("ZIP/Office/APK Archive","MS Office 97-2003 (OLE)"):
        if cb: cb("meta",f"  → Metadatos Office: {path.name}")
        for h in _meta_office(path):
            h["modulo"]="meta"; hallazgos.append(h)

    elif tipo in ("Windows PE Executable","Linux ELF Executable") or ext in (".exe",".dll",".so",".elf"):
        if cb: cb("meta",f"  → Analizando ejecutable: {path.name}")
        for h in _analizar_exe(path):
            h["modulo"]="meta"; hallazgos.append(h)

    else:
        # Archivo genérico — extraer strings básicas
        if cb: cb("meta",f"  → Archivo genérico: {path.name}")
        try:
            if shutil.which("strings"):
                r = subprocess.run(["strings","-n","8",str(path)],
                                   capture_output=True,text=True,timeout=10)
                urls = re.findall(r"https?://[^\s\"'<>]{8,}", r.stdout)
                emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]+", r.stdout)
                if urls:
                    hallazgos.append({"modulo":"meta","severidad":"info",
                        "titulo":f"URLs en archivo ({len(urls)})",
                        "descripcion":"\n".join(urls[:10]),"evidencia":urls[0]})
                if emails:
                    hallazgos.append({"modulo":"meta","severidad":"bajo",
                        "titulo":f"Emails en archivo ({len(emails)})",
                        "descripcion":"\n".join(emails[:10]),"evidencia":emails[0]})
        except: pass

    return hallazgos

def run_carpeta(ruta, cb):
    """Analiza todos los archivos en una carpeta (recursivo)."""
    hallazgos = []
    ruta = Path(ruta)
    if not ruta.exists():
        return [{"modulo":"meta","severidad":"info","titulo":"Ruta no encontrada",
                 "descripcion":str(ruta),"evidencia":""}]

    archivos = list(ruta.rglob("*"))
    archivos = [a for a in archivos if a.is_file()]
    cb("meta",f"▶ Analizando {len(archivos)} archivos en {ruta}...")

    # Estadísticas generales
    total_size = sum(a.stat().st_size for a in archivos)
    exts = {}
    for a in archivos:
        e = a.suffix.lower() or "(sin extensión)"
        exts[e] = exts.get(e,0)+1
    ext_str = ", ".join(f"{e}:{n}" for e,n in sorted(exts.items(),key=lambda x:-x[1])[:15])
    hallazgos.append({"modulo":"meta","severidad":"info",
        "titulo":f"Carpeta analizada: {ruta.name}",
        "descripcion":f"{len(archivos)} archivos | {total_size/1024/1024:.1f} MB\nExtensiones: {ext_str}",
        "evidencia":str(ruta)})

    # Archivos sospechosos por extensión
    SOSPECHOSOS_EXT = {
        ".exe":("alto","Ejecutable Windows"),".bat":("alto","Script batch"),
        ".ps1":("alto","PowerShell script"),".vbs":("alto","VBScript"),
        ".js":("medio","JavaScript"),".jar":("medio","Java Archive"),
        ".sh":("medio","Shell script"),".py":("bajo","Python script"),
        ".php":("medio","PHP script"),".asp":("medio","ASP script"),
    }
    for a in archivos:
        if a.suffix.lower() in SOSPECHOSOS_EXT:
            sev, desc = SOSPECHOSOS_EXT[a.suffix.lower()]
            hallazgos.append({"modulo":"meta","severidad":sev,
                "titulo":f"{desc} encontrado: {a.name}",
                "descripcion":f"Ruta: {a}","evidencia":str(a)})

    # Archivos ocultos
    ocultos = [a for a in archivos if a.name.startswith(".")]
    if ocultos:
        hallazgos.append({"modulo":"meta","severidad":"bajo",
            "titulo":f"Archivos ocultos ({len(ocultos)})",
            "descripcion":"\n".join(str(a) for a in ocultos[:10]),
            "evidencia":str(ocultos[0]) if ocultos else ""})

    # Permisos peligrosos (Linux)
    try:
        for a in archivos:
            modo = a.stat().st_mode
            if modo & 0o002:
                hallazgos.append({"modulo":"meta","severidad":"alto",
                    "titulo":f"Archivo escribible por todos: {a.name}",
                    "descripcion":f"Permisos: {oct(modo)} — cualquier usuario puede modificarlo.",
                    "evidencia":str(a)})
            if modo & 0o4000:
                hallazgos.append({"modulo":"meta","severidad":"critico",
                    "titulo":f"SUID detectado: {a.name}",
                    "descripcion":"Archivo SUID — se ejecuta con permisos del propietario.",
                    "evidencia":str(a)})
    except: pass

    # Analizar archivos con metadatos (imágenes, PDFs, docs, exes)
    META_EXTS = {".jpg",".jpeg",".png",".gif",".pdf",".docx",".xlsx",
                 ".pptx",".exe",".dll",".so"}
    for a in archivos:
        if a.suffix.lower() in META_EXTS and a.stat().st_size < 100*1024*1024:
            hallazgos += analizar_archivo(a, cb)

    cb("meta",f"✔ Metadatos: {len(hallazgos)} hallazgos")
    return hallazgos

def run(target, cb):
    """Entry point genérico — decide si es archivo o carpeta."""
    p = Path(target)
    if p.is_dir():
        return run_carpeta(target, cb)
    elif p.is_file():
        return analizar_archivo(target, cb)
    else:
        return []
