#!/usr/bin/env python3
"""
analizar_web.py
Lab 1.2 - Análisis Forense de Logs Web (Apache access.log)

Detecta:
  - Escaneo de directorios (>20 rutas distintas en <60s desde la misma IP)
  - Códigos de respuesta 4xx y 5xx agrupados por IP
  - Posibles intentos de SQL Injection en la URL

Genera reporte_web.json con los hallazgos.
"""

import re
import json
from datetime import datetime
from collections import defaultdict

LOG_PATH = "access.log"
REPORT_PATH = "reporte_web.json"

# Patrones de SQL Injection a buscar en la URL (case-insensitive)
SQLI_PATTERNS = [r"UNION", r"SELECT", r"--", r"OR\s+1=1", r"'"]
SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)

# Regex para Combined Log Format:
# IP - - [fecha] "METODO RUTA PROTOCOLO" CODIGO BYTES "referer" "user-agent"
LOG_REGEX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<fecha>[^\]]+)\] '
    r'"(?P<metodo>\S+) (?P<ruta>\S+) (?P<protocolo>[^"]+)" '
    r'(?P<codigo>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

APACHE_DATE_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parsear_log(path):
    """Lee el access.log y devuelve una lista de diccionarios con cada petición."""
    registros = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            m = LOG_REGEX.match(linea.strip())
            if not m:
                continue
            data = m.groupdict()
            try:
                data["fecha_dt"] = datetime.strptime(data["fecha"], APACHE_DATE_FMT)
            except ValueError:
                continue
            data["codigo"] = int(data["codigo"])
            registros.append(data)
    return registros


def detectar_escaneo_directorios(registros, max_rutas=20, ventana_seg=60):
    """
    Detecta IPs que solicitan más de `max_rutas` rutas distintas
    en una ventana de `ventana_seg` segundos.
    """
    por_ip = defaultdict(list)
    for r in registros:
        por_ip[r["ip"]].append(r)

    hallazgos = []
    for ip, eventos in por_ip.items():
        eventos.sort(key=lambda x: x["fecha_dt"])
        n = len(eventos)
        izquierda = 0
        rutas_ventana = {}  # ruta -> timestamp, para mantener la ventana deslizante

        for derecha in range(n):
            rutas_ventana[eventos[derecha]["ruta"]] = eventos[derecha]["fecha_dt"]

            # Deslizar ventana: quitar eventos fuera de los ventana_seg segundos
            while (eventos[derecha]["fecha_dt"] - eventos[izquierda]["fecha_dt"]).total_seconds() > ventana_seg:
                izquierda += 1

            rutas_distintas = {eventos[i]["ruta"] for i in range(izquierda, derecha + 1)}

            if len(rutas_distintas) > max_rutas:
                hallazgos.append({
                    "ip": ip,
                    "rutas_distintas": len(rutas_distintas),
                    "ventana_inicio": eventos[izquierda]["fecha_dt"].isoformat(),
                    "ventana_fin": eventos[derecha]["fecha_dt"].isoformat(),
                })
                break  # con un hallazgo por IP es suficiente

    return hallazgos


def agrupar_codigos_error(registros):
    """Agrupa códigos 4xx y 5xx por IP."""
    errores_por_ip = defaultdict(lambda: defaultdict(int))
    for r in registros:
        codigo = r["codigo"]
        if 400 <= codigo < 600:
            errores_por_ip[r["ip"]][str(codigo)] += 1

    resultado = []
    for ip, codigos in errores_por_ip.items():
        total = sum(codigos.values())
        resultado.append({
            "ip": ip,
            "total_errores": total,
            "codigos": dict(codigos),
        })
    resultado.sort(key=lambda x: x["total_errores"], reverse=True)
    return resultado


def detectar_sqli(registros):
    """Busca patrones de SQL Injection en la ruta solicitada."""
    hallazgos = []
    for r in registros:
        if SQLI_REGEX.search(r["ruta"]):
            patrones_encontrados = SQLI_REGEX.findall(r["ruta"])
            hallazgos.append({
                "ip": r["ip"],
                "fecha": r["fecha_dt"].isoformat(),
                "ruta": r["ruta"],
                "metodo": r["metodo"],
                "patrones": list(set(patrones_encontrados)),
            })
    return hallazgos


def main():
    registros = parsear_log(LOG_PATH)
    print(f"Total de líneas parseadas correctamente: {len(registros)}\n")

    # --- Escaneo de directorios ---
    escaneos = detectar_escaneo_directorios(registros)
    print("=== ESCANEO DE DIRECTORIOS DETECTADO ===")
    if escaneos:
        for h in escaneos:
            print(f"[ALERTA] IP: {h['ip']} — {h['rutas_distintas']} rutas distintas "
                  f"en <60s ({h['ventana_inicio']} -> {h['ventana_fin']})")
    else:
        print("No se detectaron patrones de escaneo de directorios.")
    print()

    # --- Códigos 4xx/5xx por IP ---
    errores = agrupar_codigos_error(registros)
    print("=== TOP IPs CON ERRORES 4xx/5xx ===")
    for e in errores[:10]:
        print(f"{e['ip']} -> {e['total_errores']} errores {e['codigos']}")
    print()

    # --- SQL Injection ---
    sqli = detectar_sqli(registros)
    print("=== INTENTOS DE SQL INJECTION DETECTADOS ===")
    if sqli:
        for s in sqli:
            print(f"[ALERTA] IP: {s['ip']} — Ruta: {s['ruta']} — Patrones: {s['patrones']}")
    else:
        print("No se detectaron intentos de SQL Injection.")
    print()

    # --- Reporte JSON ---
    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_peticiones_analizadas": len(registros),
        "escaneo_directorios": escaneos,
        "errores_4xx_5xx_por_ip": errores,
        "intentos_sql_injection": sqli,
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=4, ensure_ascii=False)

    print(f"Reporte exportado a {REPORT_PATH}")


if __name__ == "__main__":
    main()
