# 🔍 audit_box

Herramienta de auditoría de seguridad con interfaz web (Flask). Recibe un objetivo — **IP, URL, archivo o carpeta** — detecta su tipo y ejecuta los módulos de análisis correspondientes, generando un informe HTML con hallazgos clasificados por severidad.

> ⚠️ **Uso exclusivo en sistemas propios o con autorización expresa.** Escanear equipos o sitios de terceros sin permiso puede ser ilegal.

---

## Módulos

| Módulo | Archivo | Qué revisa |
|---|---|---|
| **DNS & WHOIS** | `modules/dns.py` | Registros A, MX, NS, TXT, CNAME, SOA · WHOIS · intento de transferencia de zona (AXFR) · enumeración de subdominios comunes · SPF, DMARC y DKIM |
| **Red** | `modules/net.py` | Escaneo con **nmap**: puertos, servicios, versiones, SO y scripts básicos de vulnerabilidades · marca puertos de riesgo (Telnet, FTP, SMB/445, RPC, etc.) |
| **Web** | `modules/web.py` | Cabeceras de seguridad (HSTS, X-Frame-Options, CSP…) · SSL/TLS · cookies · rutas sensibles · `robots.txt` · métodos HTTP · tecnologías (whatweb / nikto) |
| **Metadatos** | `modules/meta.py` | EXIF y GPS en imágenes · metadatos de PDF y documentos Office/LibreOffice · ejecutables PE/ELF · hashes · tipo real por *magic bytes* · strings |

`scanner.py` actúa como orquestador: identifica el tipo de objetivo y lanza los módulos adecuados. `report_generator.py` arma el informe.

## Instalación

Pensado para Kali Linux / Debian / Ubuntu:

```bash
chmod +x instalar.sh
./instalar.sh
```

El script instala `nmap`, `nikto`, `whatweb`, `nuclei` y las dependencias de Python. Solo para Python:

```bash
pip install -r requirements.txt
```

## Uso

```bash
python3 app.py
```

Abre `http://localhost:5000`, ingresa el objetivo y sigue el progreso en vivo. Al terminar puedes ver el informe HTML (`/scan/<id>/reporte`) o descargar el resultado en JSON (`/scan/<id>/json`).

## Estructura

```
audit_box/
├── app.py               Dashboard web (Flask)
├── scanner.py           Orquestador de módulos
├── report_generator.py  Informe HTML
├── modules/
│   ├── dns.py
│   ├── net.py
│   ├── web.py
│   └── meta.py
├── instalar.sh
└── requirements.txt
```

## Autor

**Marco Berríos Vera** — Técnico en Informática, mención Ciberseguridad.
