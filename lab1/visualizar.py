#!/usr/bin/env python3
"""
visualizar.py
Lab 1.3 - Visualización de hallazgos de seguridad

Genera 3 gráficas:
  1. Barras   - Top 10 IPs con más intentos fallidos SSH
  2. Línea    - Peticiones HTTP por hora durante el día analizado
  3. Heatmap  - Peticiones HTTP por hora y código de respuesta (200, 301, 404, 500)

Lee reporte_ssh.json y access.log. Guarda las imágenes en graficas/.
"""

import json
import re
from datetime import datetime
from collections import defaultdict

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

SSH_REPORT_PATH = "reporte_ssh.json"
ACCESS_LOG_PATH = "access.log"
GRAFICAS_DIR = "graficas"

LOG_REGEX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<fecha>[^\]]+)\] '
    r'"(?P<metodo>\S+) (?P<ruta>\S+) (?P<protocolo>[^"]+)" '
    r'(?P<codigo>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)
APACHE_DATE_FMT = "%d/%b/%Y:%H:%M:%S %z"

CODIGOS_INTERES = [200, 301, 404, 500]


def graficar_top10_ssh():
    """Gráfico de barras: Top 10 IPs con más intentos fallidos SSH."""
    with open(SSH_REPORT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    ips_sospechosas = data.get("ips_sospechosas", [])
    ips_sospechosas.sort(key=lambda x: x["intentos"], reverse=True)
    top10 = ips_sospechosas[:10]

    ips = [item["ip"] for item in top10]
    intentos = [item["intentos"] for item in top10]

    plt.figure(figsize=(10, 6))
    colores = ["#d62728" if item.get("alerta") else "#1f77b4" for item in top10]
    plt.bar(ips, intentos, color=colores)
    plt.title("Top 10 IPs con más intentos fallidos SSH")
    plt.xlabel("Dirección IP")
    plt.ylabel("Intentos fallidos")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(f"{GRAFICAS_DIR}/top10_ssh.png", dpi=150)
    plt.close()
    print(f"[OK] Gráfica generada: {GRAFICAS_DIR}/top10_ssh.png")


def parsear_access_log():
    """Lee access.log y devuelve lista de (datetime, codigo)."""
    registros = []
    with open(ACCESS_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            m = LOG_REGEX.match(linea.strip())
            if not m:
                continue
            data = m.groupdict()
            try:
                fecha_dt = datetime.strptime(data["fecha"], APACHE_DATE_FMT)
            except ValueError:
                continue
            registros.append((fecha_dt, int(data["codigo"])))
    return registros


def graficar_timeline_http(registros):
    """Línea de tiempo: peticiones HTTP por hora."""
    por_hora = defaultdict(int)
    for fecha_dt, _ in registros:
        clave_hora = fecha_dt.strftime("%Y-%m-%d %H:00")
        por_hora[clave_hora] += 1

    horas_ordenadas = sorted(por_hora.keys())
    conteos = [por_hora[h] for h in horas_ordenadas]
    etiquetas = [h.split(" ")[1] for h in horas_ordenadas]  # solo HH:00

    plt.figure(figsize=(12, 6))
    plt.plot(etiquetas, conteos, marker="o", color="#2ca02c")
    plt.title("Peticiones HTTP por hora")
    plt.xlabel("Hora del día")
    plt.ylabel("Número de peticiones")
    plt.xticks(rotation=45, ha="right")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{GRAFICAS_DIR}/timeline_http.png", dpi=150)
    plt.close()
    print(f"[OK] Gráfica generada: {GRAFICAS_DIR}/timeline_http.png")


def graficar_heatmap_http(registros):
    """Heatmap: peticiones por hora y código de respuesta (200, 301, 404, 500)."""
    matriz = defaultdict(lambda: defaultdict(int))
    for fecha_dt, codigo in registros:
        if codigo in CODIGOS_INTERES:
            hora = fecha_dt.strftime("%H:00")
            matriz[hora][codigo] += 1

    horas_ordenadas = sorted(matriz.keys())
    df = pd.DataFrame(
        [[matriz[h].get(c, 0) for c in CODIGOS_INTERES] for h in horas_ordenadas],
        index=horas_ordenadas,
        columns=[str(c) for c in CODIGOS_INTERES],
    )

    plt.figure(figsize=(8, 10))
    sns.heatmap(df, annot=True, fmt="d", cmap="YlOrRd", cbar_kws={"label": "Peticiones"})
    plt.title("Peticiones HTTP por hora y código de respuesta")
    plt.xlabel("Código de respuesta")
    plt.ylabel("Hora del día")
    plt.tight_layout()
    plt.savefig(f"{GRAFICAS_DIR}/heatmap_http.png", dpi=150)
    plt.close()
    print(f"[OK] Gráfica generada: {GRAFICAS_DIR}/heatmap_http.png")


def main():
    print("Generando gráficas...\n")

    graficar_top10_ssh()

    registros = parsear_access_log()
    print(f"Líneas de access.log parseadas: {len(registros)}")

    graficar_timeline_http(registros)
    graficar_heatmap_http(registros)

    print("\nTodas las gráficas se guardaron en la carpeta graficas/")


if __name__ == "__main__":
    main()
