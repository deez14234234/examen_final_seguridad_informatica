import re
import json
from datetime import datetime
from collections import defaultdict

# Ruta del log
LOG_FILE = "auth.log"

# Regex para IP y failed password
pattern_ip = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")
failed_pattern = "Failed password"

ip_counts = defaultdict(int)

# Leer archivo
with open(LOG_FILE, "r") as file:
    for line in file:
        if failed_pattern in line:
            match = pattern_ip.search(line)
            if match:
                ip = match.group(1)
                ip_counts[ip] += 1

# Ordenar IPs por intentos
sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

# Top 10
top_10 = sorted_ips[:10]

# Alertas
alerts = []
for ip, count in sorted_ips:
    if count > 50:
        print(f"[ALERTA] IP: {ip} — {count} intentos fallidos — Posible ataque de fuerza bruta")

    alerts.append({
        "ip": ip,
        "intentos": count,
        "alerta": count > 50
    })

# JSON output
output = {
    "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "total_intentos_fallidos": sum(ip_counts.values()),
    "ips_sospechosas": alerts
}

with open("reporte_ssh.json", "w") as f:
    json.dump(output, f, indent=4)

# Mostrar ranking
print("\nTOP 10 IPs:")
for ip, count in top_10:
    print(ip, "->", count)
