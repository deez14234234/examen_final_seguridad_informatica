Examen Práctico Final — Seguridad Informática
Estudiante: David Robert Yucra Mamani
Repositorio: examen-practico-yucra-mamani
Curso: Seguridad Informática
Unidad IV: Monitoreo de Seguridad, SIEM e Inteligencia Artificial
Modalidad elegida: AWS Education / AWS Educate por recursos limitados en PC local.

1. Justificación de uso de AWS
Se eligió AWS porque la evaluación requiere herramientas que consumen recursos elevados, especialmente Wazuh, dashboards y Jupyter. Mi equipo personal no cuenta con capacidad suficiente para ejecutar cómodamente todos los servicios solicitados.

Especificaciones de mi equipo personal:

Procesador: colocar aquí tu CPU
RAM: colocar aquí tu RAM
Disco disponible: colocar aquí tu espacio libre
Motivo: recursos insuficientes para ejecutar Wazuh / dashboard / ML de forma local.
2. Entorno AWS utilizado
Completar con tus datos reales de AWS:

Recurso	Valor
Región	us-east-1
AMI	Ubuntu Server 22.04 LTS
Instancia Lab 1 y Lab 3	t3.micro / t3.small / t3.medium
Instancia Lab 2 y Lab 4	t3.medium mínimo, recomendado t3.large si Wazuh se queda sin memoria
ID instancia Python	i-xxxxxxxxxxxxxxxxx
ID instancia Wazuh	i-xxxxxxxxxxxxxxxxx
IP pública Python	x.x.x.x
IP pública Wazuh	x.x.x.x
3. Puertos sugeridos en Security Group
Por seguridad, en SSH usa My IP, no 0.0.0.0/0, salvo que el docente lo pida para revisión temporal.

Puerto	Servicio	Origen recomendado
22	SSH	My IP
443	Wazuh Dashboard / OpenSearch Dashboards	My IP
5601	Kibana/OpenSearch si aplica	My IP
3000	Grafana si se usa Grafana	My IP
80	HTTP opcional	My IP
4. Preparación general del repositorio
mkdir examen-practico-yucra
cd examen-practico-yucra
git init
Si usas este paquete base, copia todos los archivos dentro de tu carpeta y luego ejecuta:

git add .
git commit -m "estructura inicial del examen practico"
Conecta tu repositorio remoto:

git branch -M main
git remote add origin https://github.com/TU_USUARIO/examen-practico-yucra.git
git push -u origin main
5. Instalación de Python y librerías
chmod +x scripts/setup_python.sh
./scripts/setup_python.sh
source .venv/bin/activate
Verificar:

python --version
pip freeze
6. Descargar datos del repositorio del docente
chmod +x scripts/descargar_datos.sh
./scripts/descargar_datos.sh
Archivos descargados:

lab1/auth.log
lab1/access.log
lab2/simular_bruteforce.sh
lab3/network_traffic.csv
Laboratorio 1 — Análisis Forense de Logs con Python
1.1 Análisis de SSH
source .venv/bin/activate
python lab1/analizar_ssh.py
cat lab1/reporte_ssh.json
Evidencias requeridas:

lab1/evidencias/SCR-1.1a_ssh_ejecucion.png: terminal ejecutando el script y alertas visibles.
lab1/evidencias/SCR-1.1b_ssh_json.png: contenido de reporte_ssh.json.
1.2 Análisis Web Apache
python lab1/analizar_web.py
cat lab1/reporte_web.json
Evidencias requeridas:

lab1/evidencias/SCR-1.2a_web_ejecucion.png: ejecución con detecciones de escaneo y SQLi.
lab1/evidencias/SCR-1.2b_web_json.png: contenido de reporte_web.json.
1.3 Visualizaciones
python lab1/visualizar.py
ls -lh lab1/graficas/
Archivos generados:

lab1/graficas/top10_ssh.png
lab1/graficas/timeline_http.png
lab1/graficas/heatmap_http.png
Commit recomendado:

git add lab1 README.md
git commit -m "lab1 analisis forense de logs y graficas"
git push
Laboratorio 2 — Reglas de Correlación en Wazuh
2.1 Instalar Wazuh All-in-One en EC2
En la instancia de Wazuh:

chmod +x scripts/instalar_wazuh_all_in_one.sh
./scripts/instalar_wazuh_all_in_one.sh
Al finalizar, guarda el usuario/contraseña que muestra el instalador.

Verificar servicios:

sudo systemctl status wazuh-manager --no-pager
sudo systemctl status wazuh-indexer --no-pager
sudo systemctl status wazuh-dashboard --no-pager
Evidencia:

lab2/evidencias/SCR-2.1_wazuh_activo.png
2.2 Aplicar reglas locales
chmod +x scripts/aplicar_reglas_wazuh.sh
./scripts/aplicar_reglas_wazuh.sh
Validación XML manual:

xmllint --noout lab2/local_rules_ssh.xml && echo OK
xmllint --noout lab2/local_rules_exfil.xml && echo OK
Evidencia:

lab2/evidencias/SCR-2.2_reglas_validadas.png
2.3 Simular fuerza bruta y revisar alerta
chmod +x lab2/simular_bruteforce.sh
sudo ./lab2/simular_bruteforce.sh
sudo tail -f /var/ossec/logs/alerts/alerts.log
También puedes buscar la regla:

sudo grep -n "100001\|fuerza bruta\|brute" /var/ossec/logs/alerts/alerts.log | tail -20
Evidencia:

lab2/evidencias/SCR-2.3_alerta_disparada.png
Commit recomendado:

git add lab2 scripts README.md
git commit -m "lab2 reglas wazuh y evidencia de correlacion"
git push
Laboratorio 3 — Modelo de Detección de Anomalías con ML
3.1 Abrir Jupyter
source .venv/bin/activate
jupyter notebook --ip=0.0.0.0 --port=8888 --no-browser
Abre la URL con token en tu navegador. En AWS, asegúrate de abrir temporalmente el puerto 8888 solo para tu IP, o usa túnel SSH:

ssh -i TU_LLAVE.pem -L 8888:localhost:8888 ubuntu@IP_PUBLICA_EC2
Luego abre:

http://localhost:8888
Ejecuta todas las celdas de:

lab3/deteccion_anomalias.ipynb
El notebook genera:

EDA y histogramas.
Modelo Isolation Forest.
Métricas: Precision, Recall, F1-Score y matriz de confusión.
Curva umbral vs F1.
Top 10 anomalías.
lab3/modelo_anomalias.pkl.
Evidencias:

lab3/evidencias/SCR-3.1_eda.png
lab3/evidencias/SCR-3.2_metricas.png
lab3/evidencias/SCR-3.3_umbral_f1.png
3.4 Probar script de predicción
python lab3/predecir.py lab3/nuevo_trafico.csv
Evidencia:

lab3/evidencias/SCR-3.4_predecir.png
Commit recomendado:

git add lab3 README.md requirements.txt
git commit -m "lab3 modelo isolation forest para deteccion de anomalias"
git push
Laboratorio 4 — Dashboard de Monitoreo SOC
Herramienta elegida
Se elige OpenSearch Dashboards / Wazuh Dashboard, porque al instalar Wazuh All-in-One ya queda disponible un dashboard web y los índices wazuh-alerts-*, evitando instalar otra herramienta adicional en una PC con pocos recursos.

URL típica:

https://IP_PUBLICA_EC2
4.1 Fuente de datos
En Wazuh Dashboard / OpenSearch Dashboards:

Inicia sesión.
Verifica que existan eventos en wazuh-alerts-*.
Explora eventos de las últimas 24 horas.
Exporta 20 registros representativos a CSV si la interfaz lo permite; si no, puedes documentar la búsqueda y guardar captura.
Evidencia:

lab4/evidencias/SCR-4.1_fuente_datos.png
4.2 Visualizaciones requeridas
Crear estas 4 visualizaciones:

Código	Tipo	Métrica	Agrupación
V1	Vertical Bar	Count de alertas	rule.level
V2	Data Table	Top 10 IPs con más alertas	data.srcip
V3	Line	Alertas por hora	@timestamp, intervalo 1h
V4	Pie Chart	Distribución por tipo de regla	rule.groups
Evidencia:

lab4/evidencias/SCR-4.2_visualizaciones.png
4.3 Dashboard integrado
Nombre exacto:

SOC - Monitor de Seguridad
Debe incluir:

Las 4 visualizaciones.
Rango global: últimas 24 horas.
Panel de texto con autor: David Robert Yucra Mamani.
Export JSON: reemplaza lab4/dashboard_soc.json por el export real de la herramienta.
Evidencia:

lab4/evidencias/SCR-4.3_dashboard.png
4.4 Alerta de umbral
Condición equivalente:

Alertas con rule.level >= 10 superan 5 eventos en 5 minutos
Evidencia:

lab4/evidencias/SCR-4.4_alerta.png
Commit recomendado:

git add lab4 README.md
git commit -m "lab4 dashboard soc y alerta de umbral"
git push
Checklist final antes de entregar
git status
find . -maxdepth 3 -type f | sort
Verifica que existan:

README.md
lab1/analizar_ssh.py
lab1/analizar_web.py
lab1/visualizar.py
lab1/reporte_ssh.json
lab1/reporte_web.json
lab1/graficas/top10_ssh.png
lab1/graficas/timeline_http.png
lab1/graficas/heatmap_http.png
lab2/local_rules_ssh.xml
lab2/local_rules_exfil.xml
lab3/deteccion_anomalias.ipynb
lab3/predecir.py
lab3/modelo_anomalias.pkl
lab4/dashboard_soc.json exportado desde la herramienta
Capturas en carpetas evidencias/
Último push:

git add .
git commit -m "entrega final examen practico seguridad informatica"
git push
