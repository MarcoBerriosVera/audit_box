"""
audit_box — Orquestador Fase 1
================================
Detecta tipo de objetivo y lanza los módulos correspondientes.
"""
import re
from pathlib import Path
from modules import net, web, dns, meta


def detectar_tipo(objetivo: str) -> str:
    """ip | url | archivo | carpeta"""
    p = Path(objetivo)
    if p.is_dir():  return "carpeta"
    if p.is_file(): return "archivo"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", objetivo): return "ip"
    return "url"  # dominio o URL


MODULOS_FASE1 = {
    "ip":      ["red", "dns"],
    "url":     ["dns", "web", "red"],
    "archivo": ["meta"],
    "carpeta": ["meta"],
}


def auditar(objetivo: str, callback=None) -> dict:
    def cb(modulo, msg):
        if callback: callback(modulo, msg)

    tipo = detectar_tipo(objetivo)
    cb("sistema", f"Objetivo detectado: {objetivo} → tipo: {tipo}")

    hallazgos = []
    modulos_activos = MODULOS_FASE1.get(tipo, ["web"])

    if "red" in modulos_activos:
        host = re.sub(r"https?://", "", objetivo).split("/")[0].split(":")[0]
        hallazgos += net.run(host, cb)

    if "dns" in modulos_activos:
        host = re.sub(r"https?://", "", objetivo).split("/")[0].split(":")[0]
        hallazgos += dns.run(host, cb)

    if "web" in modulos_activos:
        hallazgos += web.run(objetivo, cb)

    if "meta" in modulos_activos:
        hallazgos += meta.run(objetivo, cb)

    # Ordenar por severidad
    SEV = {"critico":0,"alto":1,"medio":2,"bajo":3,"info":4}
    hallazgos.sort(key=lambda h: SEV.get(h.get("severidad","info"), 4))

    resumen = {s: sum(1 for h in hallazgos if h.get("severidad")==s)
               for s in ("critico","alto","medio","bajo","info")}

    cb("done", f"Completado — {sum(resumen.values())} hallazgos")
    return {"objetivo": objetivo, "tipo": tipo,
            "resumen": resumen, "hallazgos": hallazgos}
