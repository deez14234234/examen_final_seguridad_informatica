<div align="center">

# Examen Práctico Final — Seguridad Informática
### Unidad IV: Monitoreo de Seguridad, SIEM e Inteligencia Artificial

**Denilson Mamani Flores**
Ingeniería de Sistemas — Ciclo IX

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.x-1E96D8?logo=wazuh&logoColor=white)](https://wazuh.com/)
[![Jupyter](https://img.shields.io/badge/Jupyter-Notebook-F37626?logo=jupyter&logoColor=white)](https://jupyter.org/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-Isolation%20Forest-F7931E?logo=scikitlearn&logoColor=white)](https://scikit-learn.org/)

</div>

---

## Descripción general

Este repositorio contiene la evaluación práctica final del curso de **Seguridad Informática**, correspondiente a la Unidad IV. El trabajo integra cuatro laboratorios que cubren el ciclo completo de un flujo de monitoreo de seguridad: análisis forense de logs, correlación de eventos en un SIEM (Wazuh), detección de anomalías con Machine Learning y construcción de un dashboard SOC.

| Laboratorio | Tema | Puntaje |
|---|---|---|
| Lab 1 | Análisis forense de logs con Python | 5 pts |
| Lab 2 | Reglas de correlación en Wazuh | 4 pts |
| Lab 3 | Detección de anomalías con Isolation Forest | 6 pts |
| Lab 4 | Dashboard de monitoreo SOC | 5 pts |
| **Total** | | **20 pts** |

---

## Entorno de trabajo

El examen se desarrolló íntegramente en un entorno **local con VirtualBox**, usando dos máquinas virtuales Ubuntu Server conectadas en red host-only, en lugar de AWS.

| Rol | IP | Usado en | Descripción |
|---|---|---|---|
| VM Endpoint / Python | `192.168.56.101` | Lab 1 y Lab 3 | Análisis de logs, scripts Python y Jupyter Notebook |
| VM Wazuh | `192.168.56.103` | Lab 2 y Lab 4 | Wazuh Manager, Indexer, Dashboard y reglas de correlación |

Acceso por SSH:

```bash
ssh denis@192.168.56.101   # VM endpoint (Lab 1 / Lab 3)
ssh denis@192.168.56.103   # VM Wazuh (Lab 2 / Lab 4)
```

**Herramientas instaladas:**

- Ubuntu Server 22.04 LTS (x2 VMs, VirtualBox host-only network)
- Python 3.11+ con entorno virtual (`.venv`) — ver `requirements.txt`
- Wazuh (Manager, Indexer y Dashboard — instalación All-in-One)
- Jupyter Notebook
- pandas, scikit-learn, matplotlib, seaborn, joblib

---

## Estructura del repositorio

```
examen_final_seguridad_informatica/
├── README.md
├── requirements.txt
├── lab1/
│   ├── analizar_ssh.py
│   ├── analizar_web.py
│   ├── visualizar.py
│   ├── auth.log
│   ├── access.log
│   ├── reporte_ssh.json
│   ├── reporte_web.json
│   ├── graficas/
│   │   ├── top10_ssh.png
│   │   ├── timeline_http.png
│   │   └── heatmap_http.png
│   └── evidencias/
├── lab2/
│   ├── local_rules_ssh.xml
│   ├── local_rules_exfil.xml
│   └── evidencias/
├── lab3/
│   ├── deteccion_anomalias.ipynb
│   ├── predecir.py
│   ├── network_traffic.csv
│   ├── nuevo_trafico.csv
│   ├── modelo_anomalias.pkl
│   ├── scaler.pkl
│   └── evidencias/
└── lab4/
    ├── dashboard_soc.json
    ├── dashboard_soc.ndjson
    └── evidencias/
```

---

## Lab 1 — Análisis forense de logs con Python

Dos scripts procesan los logs de autenticación SSH y de acceso Apache, y un tercero genera las visualizaciones.

```bash
source .venv/bin/activate
python lab1/analizar_ssh.py
python lab1/analizar_web.py
python lab1/visualizar.py
```

**Resultados obtenidos:**

- **`analizar_ssh.py`** procesó `auth.log` y detectó **253 intentos fallidos** de autenticación en total. Se generaron alertas de fuerza bruta para las IPs con mayor actividad:

  | IP | Intentos fallidos | Alerta |
  |---|---|---|
  | `45.33.32.156` | 120 | ✔ Fuerza bruta |
  | `193.32.162.55` | 58 | ✔ Fuerza bruta |
  | `91.240.118.172` | 30 | — |

- **`analizar_web.py`** procesó `access.log` (1000 peticiones) y detectó **8 posibles intentos de SQL Injection**. No se identificaron patrones de escaneo de directorios en el rango analizado. Las IPs con más errores 4xx/5xx fueron `45.33.32.156`, `193.32.162.55` y `89.210.135.99`.

  Ejecución real:

  ```
  Total de líneas parseadas correctamente: 1000

  === ESCANEO DE DIRECTORIOS DETECTADO ===
  No se detectaron patrones de escaneo de directorios.

  === TOP IPs CON ERRORES 4xx/5xx ===
  45.33.32.156 -> 47 errores {'404': 34, '403': 10, '500': 3}
  193.32.162.55 -> 18 errores {'500': 14, '400': 4}
  89.210.135.99 -> 18 errores {'404': 10, '500': 8}
  ...

  === INTENTOS DE SQL INJECTION DETECTADOS ===
  [ALERTA] IP: 193.32.162.55 — Ruta: /login?user=admin'--&pass=x — Patrones: ["--", "'"]
  [ALERTA] IP: 193.32.162.55 — Ruta: /search?q=' — Patrones: ["'"]
  ...

  Reporte exportado a reporte_web.json
  ```

  Los 8 intentos de SQLi provinieron todos de la misma IP (`193.32.162.55`), alternando entre rutas de login y búsqueda.

- **`visualizar.py`** generó las tres gráficas requeridas en `lab1/graficas/`: ranking Top 10 de IPs SSH, línea de tiempo de peticiones HTTP y heatmap de código de respuesta por hora.

**Código clave — `analizar_ssh.py`** (conteo de intentos fallidos y alerta de fuerza bruta):

```python
pattern_ip = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")
ip_counts = defaultdict(int)

with open("auth.log", "r") as file:
    for line in file:
        if "Failed password" in line:
            match = pattern_ip.search(line)
            if match:
                ip_counts[match.group(1)] += 1

for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
    if count > 50:
        print(f"[ALERTA] IP: {ip} — {count} intentos fallidos — Posible ataque de fuerza bruta")
```

**Código clave — `analizar_web.py`** (parseo Apache Combined Log Format y detección de SQLi):

```python
LOG_REGEX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<fecha>[^\]]+)\] '
    r'"(?P<metodo>\S+) (?P<ruta>\S+) (?P<protocolo>[^"]+)" '
    r'(?P<codigo>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

SQLI_REGEX = re.compile("|".join([r"UNION", r"SELECT", r"--", r"OR\s+1=1", r"'"]), re.IGNORECASE)

def detectar_sqli(registros):
    hallazgos = []
    for r in registros:
        if SQLI_REGEX.search(r["ruta"]):
            hallazgos.append({
                "ip": r["ip"], "ruta": r["ruta"],
                "patrones": list(set(SQLI_REGEX.findall(r["ruta"]))),
            })
    return hallazgos
```

**Código clave — `visualizar.py`** (gráfico de barras Top 10 SSH):

```python
plt.figure(figsize=(10, 6))
colores = ["#d62728" if item.get("alerta") else "#1f77b4" for item in top10]
plt.bar(ips, intentos, color=colores)
plt.title("Top 10 IPs con más intentos fallidos SSH")
plt.savefig("graficas/top10_ssh.png", dpi=150)
```

---

## Lab 2 — Reglas de correlación en Wazuh

Dos reglas locales personalizadas, agregadas a `/var/ossec/etc/rules/` en la VM Wazuh (`192.168.56.103`).

**`local_rules_ssh.xml`** — Regla `100050`: detecta 10 o más fallos de autenticación SSH desde la misma IP en 60 segundos (basada en el SID base `5760`, confirmado en este entorno mediante prueba directa contra `alerts.log`). Nivel de severidad 10.

**`local_rules_exfil.xml`** — Regla compuesta de dos niveles:

1. `100051`: detecta un login SSH exitoso fuera del horario laboral (22:00–06:00).
2. `100052`: se dispara solo si, dentro de la hora siguiente y desde la misma IP, se detecta una transferencia saliente mayor a 500 MB — correlacionando ambos eventos. Nivel de severidad 14 (crítico).

Validación y prueba:

```bash
sudo xmllint --noout /var/ossec/etc/rules/local_rules_ssh.xml && echo "local_rules_ssh.xml: OK"
sudo xmllint --noout /var/ossec/etc/rules/local_rules_exfil.xml && echo "local_rules_exfil.xml: OK"
# local_rules_ssh.xml: OK
# local_rules_exfil.xml: OK

sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager
# ● wazuh-manager.service - Wazuh manager
#    Active: active (running)
```

**Simulación real del ataque de fuerza bruta**, ejecutada contra la propia VM Wazuh (`127.0.0.1`, usuario inexistente, 15 intentos):

```bash
sudo apt install sshpass -y
chmod +x simular_bruteforce.sh
./simular_bruteforce.sh 127.0.0.1 usuario_falso 15
```

Alerta real capturada en `/var/ossec/logs/alerts/alerts.log` en cuanto se superaron los 10 fallos en 60s:

```
** Alert 1782850744.109089: - pam,syslog,authentication_failed,...
Rule: 5503 (level 5) -> 'PAM: User login failed.'
Src IP: 127.0.0.1

** Alert 1782850746.109585: - syslog,sshd,authentication_failed,...
Rule: 5710 (level 5) -> 'sshd: Attempt to login using a non-existent user'
Failed password for invalid user usuario_falso from 127.0.0.1 port 46204 ssh2

Rule: 100050 (level 10) -> 'Ataque de fuerza bruta SSH detectado desde 127.0.0.1'
```

La regla `100050` disparó correctamente, confirmando la correlación por IP de origen (`same_source_ip`) dentro de la ventana de 60 segundos.

---

## Lab 3 — Detección de anomalías con Machine Learning

Notebook: `lab3/deteccion_anomalias.ipynb`, sobre el dataset `network_traffic.csv` (10,000 registros de tráfico de red).

**Pipeline:**

1. Análisis exploratorio, tratamiento de valores atípicos y creación de variables derivadas (`ratio_bytes`, `bytes_por_segundo`).
2. Normalización con `StandardScaler` (persistido en `scaler.pkl`).
3. Entrenamiento de un modelo **Isolation Forest** (`contamination=0.05`, `n_estimators=100`, `random_state=42`).
4. Evaluación contra la columna `label`:

   | Métrica | Valor |
   |---|---|
   | Precision (anomaly) | 0.57 |
   | Recall (anomaly) | 0.57 |
   | F1-Score (anomaly) | 0.57 |
   | Accuracy global | 0.96 |

5. Búsqueda de umbral óptimo sobre `decision_function`: **umbral = -0.0405**, con **F1 = 0.595**.
6. Identificación del Top 10 de registros más anómalos.
7. Exportación del modelo final a `modelo_anomalias.pkl`.

**Código clave — entrenamiento del modelo:**

```python
from sklearn.ensemble import IsolationForest

modelo = IsolationForest(contamination=0.05, n_estimators=100, random_state=42)
modelo.fit(X_scaled)

df['prediccion'] = modelo.predict(X_scaled)        # -1 = anomalía, 1 = normal
df['anomaly_score'] = modelo.decision_function(X_scaled)
```

**Código clave — búsqueda del umbral óptimo (curva Umbral vs F1):**

```python
umbrales = np.linspace(df['anomaly_score'].min(), df['anomaly_score'].max(), 100)
f1_scores = []

for u in umbrales:
    pred_u = np.where(df['anomaly_score'] < u, -1, 1)
    f1_scores.append(f1_score(y_real, pred_u, pos_label=-1, zero_division=0))

mejor_idx = np.argmax(f1_scores)
mejor_umbral = umbrales[mejor_idx]     # -0.0405
mejor_f1 = f1_scores[mejor_idx]        # 0.5950
```

**Predicción sobre tráfico nuevo — `predecir.py`:**

```python
modelo = joblib.load("modelo_anomalias.pkl")
scaler = joblib.load("scaler.pkl")

df_feat['ratio_bytes'] = df_feat['bytes_sent'] / (df_feat['bytes_recv'] + 1)
df_feat['bytes_por_segundo'] = (df_feat['bytes_sent'] + df_feat['bytes_recv']) / (df_feat['duration_sec'] + 0.01)

X_nuevo = scaler.transform(df_feat[features_completas])
df_feat['prediccion'] = modelo.predict(X_nuevo)
df_feat['anomaly_score'] = modelo.decision_function(X_nuevo)

anomalias = df_feat[df_feat['prediccion'] == -1].sort_values('anomaly_score')
```

```bash
python lab3/predecir.py lab3/nuevo_trafico.csv
```

**Ejecución real** (sobre una muestra de 50 registros tomada de `network_traffic.csv`):

```
Total de registros analizados: 50
Anomalías detectadas: 4

=== REGISTROS CLASIFICADOS COMO ANOMALÍA ===
[ANOMALÍA] score=-0.2908 | src_ip=10.0.0.141 | dst_ip=185.220.101.45 | dst_port=80  | protocol=TCP | bytes_sent=2323584650 | bytes_recv=37555
[ANOMALÍA] score=-0.2899 | src_ip=10.0.3.75  | dst_ip=108.185.19.69 | dst_port=443 | protocol=TCP | bytes_sent=3886337699 | bytes_recv=23311
[ANOMALÍA] score=-0.0694 | src_ip=10.0.3.254 | dst_ip=10.0.1.54    | dst_port=8443| protocol=TCP | bytes_sent=221152    | bytes_recv=4665453
[ANOMALÍA] score=-0.0114 | src_ip=10.0.0.93  | dst_ip=91.240.118.172 | dst_port=8080| protocol=TCP | bytes_sent=4361   | bytes_recv=2479219
```

Los registros con mayor score negativo corresponden a transferencias salientes muy por encima del promedio (`bytes_sent` en el orden de GB), consistentes con un escenario de exfiltración de datos.

---

## Lab 4 — Dashboard de monitoreo SOC

**Herramienta elegida:** Wazuh Dashboard (OpenSearch Dashboards), disponible directamente tras la instalación All-in-One de Wazuh en `192.168.56.103` — sin necesidad de instalar una herramienta adicional.

Acceso: `https://192.168.56.103` → índice `wazuh-alerts-*`.

Se construyó el dashboard **"SOC - Monitor de Seguridad"** con las 4 visualizaciones solicitadas sobre el índice `wazuh-alerts-*`:

| Código | Tipo | Métrica | Agrupación |
|---|---|---|---|
| V1 | Barras verticales | Count de alertas | `rule.level` |
| V2 | Tabla de datos | Top 10 IPs con más alertas | `data.srcip` |
| V3 | Línea | Alertas por hora | `@timestamp` (intervalo 1h) |
| V4 | Circular (Pie) | Distribución por tipo de regla | `rule.groups` |

**Evidencia real de las visualizaciones:**

- **Discover** — búsqueda por `rule.id: 100050` sobre las últimas 24h arrojó **427 hits**, confirmando que la regla de fuerza bruta SSH viene disparando de forma consistente.
- **V1** (Vertical Bar, bucket `rule.level`, orden por Count, tamaño 20) muestra la distribución real de alertas por nivel de severidad.
- **V2** (Data Table, término `data.srcip`, tamaño 10) — Top IPs con más alertas registradas:

  | IP | Alertas |
  |---|---|
  | `127.0.0.1` | 105 |
  | `192.168.56.1` | 9 |
  | `192.168.56.101` | 9 |

El dashboard incluye rango de tiempo global de últimas 24 horas, panel de texto con el nombre del autor, y una alerta de umbral configurada para disparar cuando las alertas con `rule.level >= 10` superan 5 eventos en 5 minutos.

Export del dashboard incluido en `lab4/dashboard_soc.json` y `lab4/dashboard_soc.ndjson`.

---

## Evidencias

Cada laboratorio incluye su carpeta `evidencias/` con las capturas de pantalla requeridas por la rúbrica (ejecución de scripts, reportes JSON, servicios activos, reglas validadas, alertas disparadas, notebook ejecutado y visualizaciones del dashboard).

---

## Cómo reproducir el proyecto

```bash
git clone https://github.com/deez14234234/examen_final_seguridad_informatica.git
cd examen_final_seguridad_informatica

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Lab 1
python lab1/analizar_ssh.py
python lab1/analizar_web.py
python lab1/visualizar.py

# Lab 3
jupyter notebook lab3/deteccion_anomalias.ipynb
python lab3/predecir.py lab3/nuevo_trafico.csv
```

Para Lab 2 y Lab 4 se requiere una instancia de Wazuh (Manager + Indexer + Dashboard) activa; las reglas de `lab2/` deben copiarse a `/var/ossec/etc/rules/` y el dashboard de `lab4/` puede importarse desde la interfaz de Wazuh Dashboard.

---

<div align="center">

**Denilson Mamani Flores** · Seguridad Informática · Unidad IV

</div>
