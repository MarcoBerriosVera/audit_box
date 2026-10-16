"""
audit_box — Dashboard Web (Fase 1)
====================================
Arrancar: python app.py
Abrir:    http://localhost:5000
"""
import os, uuid, json, threading, datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
import scanner

app       = Flask(__name__)
SCANS     = Path("scans");    SCANS.mkdir(exist_ok=True)
REPORTS   = Path("reports");  REPORTS.mkdir(exist_ok=True)

# ─── helpers ──────────────────────────────────────────────────────

def _load(sid):
    p = SCANS / f"{sid}.json"
    return json.loads(p.read_text("utf-8")) if p.exists() else None

def _save(sid, data):
    (SCANS / f"{sid}.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")

def _all_scans():
    scans = []
    for f in sorted(SCANS.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try: scans.append(json.loads(f.read_text("utf-8")))
        except: pass
    return scans

def _run_scan(sid, objetivo):
    def cb(mod, msg):
        d = _load(sid) or {}
        d.setdefault("log",[]).append({"mod":mod,"msg":msg,
            "ts": datetime.datetime.now().strftime("%H:%M:%S")})
        d["modulo_actual"] = mod
        _save(sid, d)

    d = _load(sid) or {}
    d["estado"] = "corriendo"
    _save(sid, d)
    try:
        result = scanner.auditar(objetivo, cb)
        # Guardar reporte HTML
        from report_generator import generar_reporte
        html = generar_reporte(result, sid)
        (REPORTS / f"{sid}.html").write_text(html, "utf-8")
        d = _load(sid) or {}
        d.update({"estado":"completado","resultado":result})
        _save(sid, d)
    except Exception as e:
        d = _load(sid) or {}
        d["estado"] = "error"
        d.setdefault("log",[]).append({"mod":"error","msg":str(e),"ts":""})
        _save(sid, d)

# ─── rutas Flask ──────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(DASHBOARD, scans=_all_scans())

@app.route("/scan", methods=["POST"])
def start_scan():
    obj = request.form.get("objetivo","").strip()
    if not obj: return redirect("/")
    sid = str(uuid.uuid4())
    _save(sid, {"scan_id":sid,"objetivo":obj,
                "fecha":datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
                "estado":"pendiente","log":[],"resultado":None})
    threading.Thread(target=_run_scan, args=(sid, obj), daemon=True).start()
    return redirect(f"/scan/{sid}")

@app.route("/scan/<sid>")
def view_scan(sid):
    d = _load(sid)
    if not d: return "No encontrado", 404
    return render_template_string(PROGRESO, d=d)

@app.route("/api/scan/<sid>")
def api_scan(sid):
    d = _load(sid)
    if not d: return jsonify({"error":"not found"}), 404
    return jsonify({"estado":d["estado"],"log":d.get("log",[])[-40:],
                    "modulo_actual":d.get("modulo_actual",""),
                    "resultado":d.get("resultado")})

@app.route("/scan/<sid>/reporte")
def reporte(sid):
    p = REPORTS / f"{sid}.html"
    return p.read_text("utf-8") if p.exists() else ("Reporte no listo aún", 404)

@app.route("/scan/<sid>/json")
def raw_json(sid):
    d = _load(sid)
    if not d: return jsonify({"error":"not found"}), 404
    return jsonify(d.get("resultado",{}))

# ─── HTML: dashboard principal ────────────────────────────────────

DASHBOARD = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>audit_box</title>
<style>
:root{--bg:#0f1117;--card:#1a1d27;--border:#2a2d3a;--accent:#4f9cf9;
     --text:#e2e8f0;--muted:#64748b;--success:#22c55e;--warn:#f59e0b;
     --danger:#ef4444;--crit:#a855f7;--radius:10px;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;}
a{color:var(--accent);text-decoration:none;}
/* Sidebar */
.layout{display:flex;min-height:100vh;}
.sidebar{width:220px;background:var(--card);border-right:1px solid var(--border);
         padding:24px 16px;flex-shrink:0;display:flex;flex-direction:column;gap:8px;}
.logo{font-size:18px;font-weight:700;color:var(--text);padding:0 8px 16px;
      border-bottom:1px solid var(--border);margin-bottom:8px;display:flex;align-items:center;gap:8px;}
.logo span{font-size:22px;}
.nav-item{padding:8px 12px;border-radius:6px;font-size:13px;color:var(--muted);
          cursor:pointer;display:flex;align-items:center;gap:8px;transition:all .15s;}
.nav-item:hover,.nav-item.active{background:rgba(79,156,249,.12);color:var(--accent);}
.main{flex:1;padding:32px;overflow-x:hidden;}
/* Cards */
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:20px;}
.card-title{font-size:14px;font-weight:600;color:var(--muted);text-transform:uppercase;
            letter-spacing:.06em;margin-bottom:16px;}
/* Form */
.input-row{display:flex;gap:10px;flex-wrap:wrap;}
input[type=text]{flex:1;min-width:200px;background:#0f1117;border:1px solid var(--border);
                 border-radius:6px;padding:10px 14px;color:var(--text);font-size:14px;outline:none;}
input[type=text]:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(79,156,249,.15);}
input::placeholder{color:var(--muted);}
button{background:var(--accent);color:#0f1117;border:none;padding:10px 20px;
       border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;white-space:nowrap;}
button:hover{opacity:.9;}
/* Badges */
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;}
.b-critico{background:rgba(168,85,247,.2);color:#d8b4fe;border:1px solid rgba(168,85,247,.3);}
.b-alto{background:rgba(239,68,68,.2);color:#fca5a5;border:1px solid rgba(239,68,68,.3);}
.b-medio{background:rgba(245,158,11,.2);color:#fcd34d;border:1px solid rgba(245,158,11,.3);}
.b-bajo{background:rgba(34,197,94,.2);color:#86efac;border:1px solid rgba(34,197,94,.3);}
.b-info{background:rgba(100,116,139,.2);color:#94a3b8;border:1px solid rgba(100,116,139,.3);}
.b-corriendo{background:rgba(79,156,249,.2);color:#93c5fd;border:1px solid rgba(79,156,249,.3);}
.b-completado{background:rgba(34,197,94,.2);color:#86efac;border:1px solid rgba(34,197,94,.3);}
.b-error{background:rgba(239,68,68,.2);color:#fca5a5;border:1px solid rgba(239,68,68,.3);}
.b-pendiente{background:rgba(100,116,139,.2);color:#94a3b8;border:1px solid rgba(100,116,139,.3);}
/* Scan list */
.scan-row{display:flex;align-items:center;justify-content:space-between;
          padding:14px 0;border-bottom:1px solid var(--border);gap:12px;flex-wrap:wrap;}
.scan-row:last-child{border-bottom:none;}
.scan-obj{font-weight:500;font-size:14px;}
.scan-date{font-size:12px;color:var(--muted);margin-top:2px;}
.sev-pills{display:flex;gap:4px;margin-top:6px;flex-wrap:wrap;}
.btn-sm{padding:5px 12px;font-size:12px;}
.btn-ghost{background:transparent;border:1px solid var(--border);color:var(--text);}
.btn-ghost:hover{background:var(--border);}
/* Empty */
.empty{text-align:center;padding:48px;color:var(--muted);}
.empty-icon{font-size:40px;margin-bottom:12px;}
/* Stats */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:10px;margin-bottom:20px;}
.stat{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
      padding:14px;text-align:center;}
.stat-num{font-size:24px;font-weight:700;}
.stat-lbl{font-size:11px;color:var(--muted);margin-top:2px;}
</style>
</head>
<body>
<div class="layout">
  <div class="sidebar">
    <div class="logo"><span>🔍</span>audit_box</div>
    <div class="nav-item active">🏠 Dashboard</div>
    <div class="nav-item" onclick="location.href='/scan/new'">➕ Nueva auditoría</div>
    <div style="margin-top:auto;padding-top:16px;border-top:1px solid var(--border);">
      <div style="font-size:11px;color:var(--muted);text-align:center;">Fase 1 · v1.0</div>
    </div>
  </div>
  <div class="main">
    <!-- STATS GLOBALES -->
    {% set total = scans|length %}
    {% set completadas = scans|selectattr('estado','eq','completado')|list|length %}
    {% set total_hallazgos = namespace(n=0) %}
    {% set total_criticos  = namespace(n=0) %}
    {% for s in scans %}
      {% if s.resultado %}
        {% set total_hallazgos.n = total_hallazgos.n + (s.resultado.resumen.critico + s.resultado.resumen.alto + s.resultado.resumen.medio + s.resultado.resumen.bajo + s.resultado.resumen.info) %}
        {% set total_criticos.n  = total_criticos.n  + s.resultado.resumen.critico %}
      {% endif %}
    {% endfor %}
    <div class="stats">
      <div class="stat"><div class="stat-num" style="color:var(--accent)">{{total}}</div><div class="stat-lbl">Auditorías</div></div>
      <div class="stat"><div class="stat-num" style="color:var(--success)">{{completadas}}</div><div class="stat-lbl">Completadas</div></div>
      <div class="stat"><div class="stat-num">{{total_hallazgos.n}}</div><div class="stat-lbl">Hallazgos totales</div></div>
      <div class="stat"><div class="stat-num" style="color:#d8b4fe">{{total_criticos.n}}</div><div class="stat-lbl">Críticos</div></div>
    </div>

    <!-- NUEVA AUDITORÍA -->
    <div class="card">
      <div class="card-title">Nueva auditoría</div>
      <form method="POST" action="/scan">
        <div class="input-row">
          <input type="text" name="objetivo"
            placeholder="IP (192.168.1.1) · URL (https://ejemplo.com) · Dominio (ejemplo.com) · Ruta local (/carpeta o C:\\ruta)"
            required>
          <button type="submit">▶ Iniciar</button>
        </div>
        <div style="font-size:12px;color:var(--muted);margin-top:8px;">
          Detecta automáticamente el tipo de objetivo (red, web, archivo o carpeta local)
        </div>
      </form>
    </div>

    <!-- HISTORIAL -->
    <div class="card">
      <div class="card-title">Historial de auditorías</div>
      {% if scans %}
        {% for s in scans %}
        <div class="scan-row">
          <div>
            <div class="scan-obj">{{s.objetivo}}</div>
            <div class="scan-date">{{s.fecha}} · {{s.scan_id[:8]}}</div>
            {% if s.resultado %}
            <div class="sev-pills">
              {% if s.resultado.resumen.critico %}<span class="badge b-critico">🔴 {{s.resultado.resumen.critico}} crítico</span>{% endif %}
              {% if s.resultado.resumen.alto %}<span class="badge b-alto">🟠 {{s.resultado.resumen.alto}} alto</span>{% endif %}
              {% if s.resultado.resumen.medio %}<span class="badge b-medio">🟡 {{s.resultado.resumen.medio}} medio</span>{% endif %}
              {% if s.resultado.resumen.bajo %}<span class="badge b-bajo">🟢 {{s.resultado.resumen.bajo}} bajo</span>{% endif %}
              {% if s.resultado.resumen.info %}<span class="badge b-info">⚪ {{s.resultado.resumen.info}} info</span>{% endif %}
            </div>
            {% endif %}
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
            <span class="badge b-{{s.estado}}">{{s.estado}}</span>
            <a href="/scan/{{s.scan_id}}"><button class="btn-sm btn-ghost">Ver</button></a>
            {% if s.estado == 'completado' %}
            <a href="/scan/{{s.scan_id}}/reporte"><button class="btn-sm">Reporte</button></a>
            {% endif %}
          </div>
        </div>
        {% endfor %}
      {% else %}
        <div class="empty">
          <div class="empty-icon">🔍</div>
          <div>Ingresa un objetivo arriba para iniciar tu primera auditoría</div>
        </div>
      {% endif %}
    </div>
  </div>
</div>
</body></html>"""

# ─── HTML: pantalla de progreso ───────────────────────────────────

PROGRESO = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Auditoría en curso — audit_box</title>
<style>
:root{--bg:#0f1117;--card:#1a1d27;--border:#2a2d3a;--accent:#4f9cf9;
     --text:#e2e8f0;--muted:#64748b;--success:#22c55e;--warn:#f59e0b;
     --danger:#ef4444;--crit:#a855f7;--radius:10px;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}
.topbar{background:var(--card);border-bottom:1px solid var(--border);
        padding:16px 24px;display:flex;align-items:center;gap:12px;}
.topbar h1{font-size:16px;font-weight:600;}
.container{max-width:900px;margin:32px auto;padding:0 16px;display:grid;
           grid-template-columns:1fr 320px;gap:16px;}
@media(max-width:700px){.container{grid-template-columns:1fr;}}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;}
.card-title{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;
            letter-spacing:.06em;margin-bottom:12px;}
/* Módulos */
.mod-grid{display:flex;flex-direction:column;gap:8px;}
.mod{display:flex;align-items:center;gap:10px;padding:10px 12px;
     border-radius:6px;background:#0f1117;border:1px solid var(--border);}
.mod-icon{font-size:18px;width:24px;text-align:center;}
.mod-name{font-size:13px;font-weight:500;flex:1;}
.mod-status{font-size:11px;color:var(--muted);}
.mod.done{border-color:rgba(34,197,94,.3);}
.mod.active{border-color:var(--accent);background:rgba(79,156,249,.08);}
/* Log */
.log{background:#060810;border-radius:6px;padding:14px;
     font-family:monospace;font-size:12px;max-height:420px;overflow-y:auto;}
.log-entry{padding:3px 0;display:flex;gap:8px;}
.log-ts{color:var(--muted);flex-shrink:0;}
.log-mod{flex-shrink:0;width:70px;text-align:right;}
.log-msg{color:#a5f3fc;}
/* Severidad */
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;}
.b-critico{background:rgba(168,85,247,.2);color:#d8b4fe;}
.b-alto{background:rgba(239,68,68,.2);color:#fca5a5;}
.b-medio{background:rgba(245,158,11,.2);color:#fcd34d;}
.b-bajo{background:rgba(34,197,94,.2);color:#86efac;}
.b-info{background:rgba(100,116,139,.2);color:#94a3b8;}
/* Hallazgos */
.finding{padding:10px 12px;border-radius:6px;border:1px solid var(--border);
         margin-bottom:8px;background:#0f1117;cursor:pointer;}
.finding:hover{border-color:var(--accent);}
.finding-header{display:flex;align-items:flex-start;gap:8px;}
.finding-title{font-size:13px;font-weight:500;flex:1;}
.finding-body{font-size:12px;color:var(--muted);margin-top:8px;
              white-space:pre-wrap;word-break:break-all;display:none;}
.finding.open .finding-body{display:block;}
/* Spinner */
@keyframes spin{to{transform:rotate(360deg)}}
.spin{display:inline-block;width:14px;height:14px;border:2px solid var(--border);
      border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;
      vertical-align:middle;margin-right:6px;}
/* Filtros */
.filters{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;}
.filter-btn{padding:4px 10px;border-radius:4px;font-size:11px;font-weight:700;
            cursor:pointer;border:1px solid var(--border);background:transparent;
            color:var(--muted);transition:all .15s;}
.filter-btn.active{border-color:var(--accent);color:var(--accent);}
.search{width:100%;padding:7px 10px;background:#0f1117;border:1px solid var(--border);
        border-radius:6px;color:var(--text);font-size:12px;outline:none;margin-bottom:10px;}
.search:focus{border-color:var(--accent);}
/* Botón reporte */
.btn-report{display:none;width:100%;margin-top:12px;background:var(--accent);color:#0f1117;
            border:none;padding:10px;border-radius:6px;font-size:14px;font-weight:700;cursor:pointer;}
.btn-report:hover{opacity:.9;}
</style>
</head>
<body>
<div class="topbar">
  <a href="/" style="color:var(--muted);font-size:13px;">← Panel</a>
  <div style="width:1px;height:20px;background:var(--border);"></div>
  <h1>🔍 {{d.objetivo}}</h1>
  <div id="estado-badge" style="margin-left:auto;font-size:12px;color:var(--muted);">
    <span class="spin" id="spin"></span><span id="estado-txt">{{d.estado}}</span>
  </div>
</div>

<div class="container">
  <!-- COLUMNA IZQUIERDA: log + hallazgos -->
  <div>
    <!-- Log en tiempo real -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-title">Log en tiempo real</div>
      <div class="log" id="log">
        {% for e in d.log %}
        <div class="log-entry">
          <span class="log-ts">{{e.ts}}</span>
          <span class="log-mod" style="color:var(--accent);">[{{e.mod}}]</span>
          <span class="log-msg">{{e.msg}}</span>
        </div>
        {% endfor %}
      </div>
    </div>

    <!-- Hallazgos -->
    <div class="card">
      <div class="card-title">Hallazgos (<span id="count">0</span>)</div>
      <div class="filters">
        <button class="filter-btn active" onclick="setFilter('todos')">Todos</button>
        <button class="filter-btn" onclick="setFilter('critico')" style="color:#d8b4fe;border-color:rgba(168,85,247,.3);">🔴 Crítico</button>
        <button class="filter-btn" onclick="setFilter('alto')"   style="color:#fca5a5;border-color:rgba(239,68,68,.3);">🟠 Alto</button>
        <button class="filter-btn" onclick="setFilter('medio')"  style="color:#fcd34d;border-color:rgba(245,158,11,.3);">🟡 Medio</button>
        <button class="filter-btn" onclick="setFilter('bajo')"   style="color:#86efac;border-color:rgba(34,197,94,.3);">🟢 Bajo</button>
        <button class="filter-btn" onclick="setFilter('info')"   style="color:#94a3b8;">⚪ Info</button>
      </div>
      <input class="search" id="search" placeholder="Buscar en hallazgos..." oninput="renderFindings()">
      <div id="findings"></div>
      <button class="btn-report" id="btn-report"
              onclick="location.href='/scan/{{d.scan_id}}/reporte'">
        📄 Ver reporte HTML completo →
      </button>
    </div>
  </div>

  <!-- COLUMNA DERECHA: módulos + resumen -->
  <div>
    <div class="card" style="margin-bottom:16px;">
      <div class="card-title">Módulos</div>
      <div class="mod-grid">
        <div class="mod" id="mod-sistema">
          <span class="mod-icon">⚙️</span>
          <div><div class="mod-name">Sistema</div><div class="mod-status" id="msg-sistema">Iniciando...</div></div>
        </div>
        <div class="mod" id="mod-red">
          <span class="mod-icon">🌐</span>
          <div><div class="mod-name">Red (nmap)</div><div class="mod-status" id="msg-red">En espera</div></div>
        </div>
        <div class="mod" id="mod-dns">
          <span class="mod-icon">🔎</span>
          <div><div class="mod-name">DNS & WHOIS</div><div class="mod-status" id="msg-dns">En espera</div></div>
        </div>
        <div class="mod" id="mod-web">
          <span class="mod-icon">🕸️</span>
          <div><div class="mod-name">Web & Headers</div><div class="mod-status" id="msg-web">En espera</div></div>
        </div>
        <div class="mod" id="mod-meta">
          <span class="mod-icon">📁</span>
          <div><div class="mod-name">Metadatos</div><div class="mod-status" id="msg-meta">En espera</div></div>
        </div>
        <div class="mod" id="mod-done">
          <span class="mod-icon">✅</span>
          <div><div class="mod-name">Completado</div><div class="mod-status" id="msg-done">—</div></div>
        </div>
      </div>
    </div>

    <div class="card" id="resumen-card">
      <div class="card-title">Resumen</div>
      <div id="resumen-content" style="color:var(--muted);font-size:13px;">
        Esperando resultados...
      </div>
    </div>
  </div>
</div>

<script>
const SID = "{{d.scan_id}}";
let allFindings = [];
let filtroActivo = "todos";
let intervalo;

function setFilter(f) {
  filtroActivo = f;
  document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
  event.target.classList.add("active");
  renderFindings();
}

function sev_class(s) {
  return "b-"+s;
}

function renderFindings() {
  const q = document.getElementById("search").value.toLowerCase();
  const filtered = allFindings.filter(h => {
    const matchSev = filtroActivo === "todos" || h.severidad === filtroActivo;
    const matchQ   = !q || h.titulo.toLowerCase().includes(q) ||
                     (h.descripcion||"").toLowerCase().includes(q) ||
                     (h.evidencia||"").toLowerCase().includes(q);
    return matchSev && matchQ;
  });
  document.getElementById("count").textContent = filtered.length;
  const SEV_ICON = {critico:"🔴",alto:"🟠",medio:"🟡",bajo:"🟢",info:"⚪"};
  document.getElementById("findings").innerHTML = filtered.map((h,i) => `
    <div class="finding" onclick="this.classList.toggle('open')">
      <div class="finding-header">
        <span class="badge ${sev_class(h.severidad)}">${SEV_ICON[h.severidad]||""} ${h.severidad.toUpperCase()}</span>
        <span class="finding-title">${h.titulo}</span>
        <span style="font-size:10px;color:var(--muted);flex-shrink:0">[${h.modulo||""}]</span>
      </div>
      <div class="finding-body">
        <div style="margin-bottom:6px;color:var(--text);">${(h.descripcion||"").replace(/\n/g,"<br>")}</div>
        ${h.evidencia?`<div style="margin-top:6px;padding:6px 8px;background:#060810;border-radius:4px;
          font-family:monospace;font-size:11px;color:#a5f3fc;word-break:break-all;">${h.evidencia}</div>`:""}
      </div>
    </div>`).join("");
}

function updateResumen(resumen) {
  if (!resumen) return;
  const total = Object.values(resumen).reduce((a,b)=>a+b,0);
  document.getElementById("resumen-content").innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
      <div style="background:#0f1117;padding:10px;border-radius:6px;text-align:center;">
        <div style="font-size:20px;font-weight:700;color:#d8b4fe">${resumen.critico}</div>
        <div style="font-size:11px;color:var(--muted);">Críticos</div>
      </div>
      <div style="background:#0f1117;padding:10px;border-radius:6px;text-align:center;">
        <div style="font-size:20px;font-weight:700;color:#fca5a5">${resumen.alto}</div>
        <div style="font-size:11px;color:var(--muted);">Altos</div>
      </div>
      <div style="background:#0f1117;padding:10px;border-radius:6px;text-align:center;">
        <div style="font-size:20px;font-weight:700;color:#fcd34d">${resumen.medio}</div>
        <div style="font-size:11px;color:var(--muted);">Medios</div>
      </div>
      <div style="background:#0f1117;padding:10px;border-radius:6px;text-align:center;">
        <div style="font-size:20px;font-weight:700;color:#86efac">${resumen.bajo}</div>
        <div style="font-size:11px;color:var(--muted);">Bajos</div>
      </div>
    </div>
    <div style="margin-top:10px;text-align:center;font-size:13px;color:var(--muted);">
      ${total} hallazgos totales
    </div>`;
}

async function poll() {
  const r = await fetch("/api/scan/"+SID);
  const data = await r.json();

  // Log
  const logDiv = document.getElementById("log");
  if (data.log) {
    logDiv.innerHTML = data.log.map(e =>
      `<div class="log-entry">
        <span class="log-ts">${e.ts}</span>
        <span class="log-mod" style="color:var(--accent);">[${e.mod}]</span>
        <span class="log-msg">${e.msg}</span>
       </div>`).join("");
    logDiv.scrollTop = logDiv.scrollHeight;
  }

  // Módulo activo
  const mod = data.modulo_actual || "";
  document.querySelectorAll(".mod").forEach(m => m.classList.remove("active","done"));
  if (mod && mod !== "done") {
    const el = document.getElementById("mod-"+mod);
    if (el) el.classList.add("active");
  }
  if (data.log) {
    data.log.forEach(e => {
      const el = document.getElementById("msg-"+e.mod);
      if (el) el.textContent = e.msg.substring(0,40);
    });
  }

  // Hallazgos
  if (data.resultado?.hallazgos) {
    allFindings = data.resultado.hallazgos;
    renderFindings();
    updateResumen(data.resultado.resumen);
  }

  // Estado final
  if (data.estado === "completado") {
    clearInterval(intervalo);
    document.getElementById("spin").style.display="none";
    document.getElementById("estado-txt").textContent = "✅ Completado";
    document.getElementById("btn-report").style.display="block";
    document.getElementById("mod-done").classList.add("done");
  } else if (data.estado === "error") {
    clearInterval(intervalo);
    document.getElementById("spin").style.display="none";
    document.getElementById("estado-txt").textContent = "❌ Error";
  }
}

poll();
intervalo = setInterval(poll, 2500);
</script>
</body></html>"""

if __name__ == "__main__":
    print("\n🔍 audit_box Fase 1 iniciado")
    print("   → http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
