"""
audit_box — Generador de Reporte HTML (Fase 1)
"""
from datetime import datetime

SEV_CONFIG = {
    "critico": {"label":"CRÍTICO","emoji":"🔴","color":"#a855f7","bg":"rgba(168,85,247,.1)","border":"rgba(168,85,247,.3)"},
    "alto":    {"label":"ALTO",   "emoji":"🟠","color":"#ef4444","bg":"rgba(239,68,68,.1)","border":"rgba(239,68,68,.3)"},
    "medio":   {"label":"MEDIO",  "emoji":"🟡","color":"#f59e0b","bg":"rgba(245,158,11,.1)","border":"rgba(245,158,11,.3)"},
    "bajo":    {"label":"BAJO",   "emoji":"🟢","color":"#22c55e","bg":"rgba(34,197,94,.1)","border":"rgba(34,197,94,.3)"},
    "info":    {"label":"INFO",   "emoji":"⚪","color":"#64748b","bg":"rgba(100,116,139,.1)","border":"rgba(100,116,139,.3)"},
}

MOD_ICONS = {
    "red":"🌐","dns":"🔎","web":"🕸️","meta":"📁","sistema":"⚙️","done":"✅",
}

def _badge(sev):
    c = SEV_CONFIG.get(sev, SEV_CONFIG["info"])
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;'
            f'font-weight:700;background:{c["bg"]};color:{c["color"]};border:1px solid {c["border"]};">'
            f'{c["emoji"]} {c["label"]}</span>')

def _finding_card(h):
    sev      = h.get("severidad","info")
    c        = SEV_CONFIG.get(sev, SEV_CONFIG["info"])
    mod      = h.get("modulo","")
    titulo   = h.get("titulo","")
    desc     = (h.get("descripcion","") or "").replace("\n","<br>")
    evidencia = h.get("evidencia","") or ""
    return f"""
    <div style="background:{c['bg']};border:1px solid {c['border']};border-radius:8px;
                padding:16px;margin-bottom:12px;">
      <div style="display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap;">
        {_badge(sev)}
        <div style="flex:1;">
          <div style="font-weight:600;font-size:14px;">{titulo}</div>
          <div style="font-size:11px;color:#64748b;margin-top:2px;">Módulo: {MOD_ICONS.get(mod,'')} {mod.upper()}</div>
        </div>
      </div>
      {f'<div style="margin-top:10px;font-size:13px;color:#cbd5e1;">{desc}</div>' if desc else ''}
      {f'<div style="margin-top:8px;padding:8px 10px;background:#0f1117;border-radius:4px;font-family:monospace;font-size:11px;color:#67e8f9;word-break:break-all;">{evidencia[:400]}</div>' if evidencia else ''}
    </div>"""

def generar_reporte(resultado: dict, scan_id: str) -> str:
    objetivo  = resultado.get("objetivo","?")
    tipo      = resultado.get("tipo","?")
    resumen   = resultado.get("resumen",{})
    hallazgos = resultado.get("hallazgos",[])
    fecha     = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    total     = sum(resumen.values())

    riesgo_general = (
        "CRÍTICO" if resumen.get("critico",0) > 0 else
        "ALTO"    if resumen.get("alto",0)    > 0 else
        "MEDIO"   if resumen.get("medio",0)   > 0 else
        "BAJO"    if resumen.get("bajo",0)    > 0 else
        "INFO"
    )
    color_riesgo = {
        "CRÍTICO":"#a855f7","ALTO":"#ef4444","MEDIO":"#f59e0b","BAJO":"#22c55e","INFO":"#64748b"
    }[riesgo_general]

    # Agrupados por módulo
    modulos = {}
    for h in hallazgos:
        m = h.get("modulo","otro")
        modulos.setdefault(m, []).append(h)

    modulos_html = ""
    for mod, items in modulos.items():
        icon = MOD_ICONS.get(mod,"📋")
        cards = "".join(_finding_card(h) for h in items)
        modulos_html += f"""
        <div style="margin-bottom:32px;">
          <h3 style="font-size:16px;font-weight:600;color:#e2e8f0;margin-bottom:16px;
                     padding-bottom:8px;border-bottom:1px solid #2a2d3a;">
            {icon} Módulo: {mod.upper()} <span style="font-size:12px;color:#64748b;font-weight:400;">({len(items)} hallazgos)</span>
          </h3>
          {cards}
        </div>"""

    # Recomendaciones automáticas
    recomendaciones = []
    sevs = {h.get("severidad") for h in hallazgos}
    titulos_lower = " ".join(h.get("titulo","").lower() for h in hallazgos)
    if "critico" in sevs or "alto" in sevs:
        recomendaciones.append("Atender de inmediato los hallazgos críticos y altos.")
    if "axfr" in titulos_lower:
        recomendaciones.append("Deshabilitar las transferencias de zona AXFR en el servidor DNS.")
    if "header" in titulos_lower:
        recomendaciones.append("Configurar headers de seguridad HTTP: HSTS, CSP, X-Frame-Options.")
    if "ssl" in titulos_lower or "tls" in titulos_lower:
        recomendaciones.append("Revisar y renovar el certificado SSL/TLS. Usar TLS 1.2 o superior.")
    if "puerto" in titulos_lower or "port" in titulos_lower:
        recomendaciones.append("Aplicar firewall y cerrar puertos que no sean necesarios.")
    if "gps" in titulos_lower or "coordenada" in titulos_lower:
        recomendaciones.append("Limpiar metadatos GPS de imágenes antes de publicarlas.")
    if not recomendaciones:
        recomendaciones.append("Mantener el sistema actualizado y realizar auditorías periódicas.")

    rec_html = "".join(f'<li style="margin:6px 0;font-size:14px;">{r}</li>' for r in recomendaciones)

    # Tarjetas de resumen
    stat_cards = ""
    for sev in ("critico","alto","medio","bajo","info"):
        c = SEV_CONFIG[sev]
        n = resumen.get(sev, 0)
        stat_cards += f"""
        <div style="background:{c['bg']};border:1px solid {c['border']};border-radius:8px;
                    padding:16px;text-align:center;min-width:90px;">
          <div style="font-size:28px;font-weight:700;color:{c['color']};">{n}</div>
          <div style="font-size:11px;color:#94a3b8;margin-top:4px;">{c['label']}</div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>audit_box — Reporte {objetivo}</title>
<style>
:root{{--bg:#0f1117;--card:#1a1d27;--border:#2a2d3a;--text:#e2e8f0;--muted:#64748b;}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}}
.wrap{{max-width:900px;margin:0 auto;padding:32px 16px;}}
a{{color:#4f9cf9;}}
@media print{{body{{background:white;color:black;}} .no-print{{display:none;}}}}
</style>
</head>
<body>
<div class="wrap">
  <!-- Header -->
  <div style="background:var(--card);border:1px solid var(--border);border-radius:12px;
              padding:32px;margin-bottom:24px;display:flex;justify-content:space-between;
              align-items:flex-start;flex-wrap:wrap;gap:16px;">
    <div>
      <div style="font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;">
        Reporte de Auditoría de Seguridad · Fase 1
      </div>
      <h1 style="font-size:22px;font-weight:700;">{objetivo}</h1>
      <div style="font-size:13px;color:var(--muted);margin-top:4px;">
        Tipo: {tipo} · Generado: {fecha} · ID: {scan_id[:8]}
      </div>
    </div>
    <div style="text-align:center;background:#0f1117;border-radius:8px;padding:16px 24px;">
      <div style="font-size:11px;color:var(--muted);margin-bottom:4px;">RIESGO GENERAL</div>
      <div style="font-size:28px;font-weight:700;color:{color_riesgo};">{riesgo_general}</div>
      <div style="font-size:12px;color:var(--muted);margin-top:4px;">{total} hallazgos</div>
    </div>
  </div>

  <!-- Resumen -->
  <div style="background:var(--card);border:1px solid var(--border);border-radius:12px;
              padding:24px;margin-bottom:24px;">
    <h2 style="font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;
               letter-spacing:.06em;margin-bottom:16px;">Resumen por severidad</h2>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">
      {stat_cards}
    </div>
  </div>

  <!-- Recomendaciones -->
  <div style="background:rgba(79,156,249,.08);border:1px solid rgba(79,156,249,.25);
              border-radius:12px;padding:20px 24px;margin-bottom:24px;">
    <h2 style="font-size:13px;font-weight:600;color:#93c5fd;text-transform:uppercase;
               letter-spacing:.06em;margin-bottom:12px;">📋 Recomendaciones</h2>
    <ul style="padding-left:20px;color:#cbd5e1;">
      {rec_html}
    </ul>
  </div>

  <!-- Hallazgos -->
  <div style="background:var(--card);border:1px solid var(--border);border-radius:12px;
              padding:24px;margin-bottom:24px;">
    <h2 style="font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;
               letter-spacing:.06em;margin-bottom:20px;">Hallazgos detallados ({total})</h2>
    {modulos_html if modulos_html else '<div style="color:var(--muted);text-align:center;padding:32px;">Sin hallazgos</div>'}
  </div>

  <!-- Footer -->
  <div style="text-align:center;font-size:12px;color:var(--muted);padding:16px;" class="no-print">
    audit_box · {fecha} ·
    <a href="/">← Volver al panel</a> ·
    <a href="javascript:window.print()">Imprimir / Guardar PDF</a>
  </div>
</div>
</body></html>"""
