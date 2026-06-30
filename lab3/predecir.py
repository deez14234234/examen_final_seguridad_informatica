#!/usr/bin/env python3
"""
predecir.py
Lab 3 - Tarea 3.4: Script de predicción con el modelo entrenado

Carga modelo_anomalias.pkl y scaler.pkl, acepta un CSV nuevo como argumento,
y muestra en consola los registros clasificados como anomalía con sus scores.

Uso:
    python predecir.py nuevo_trafico.csv
"""

import sys
import pandas as pd
import joblib

MODELO_PATH = "modelo_anomalias.pkl"
SCALER_PATH = "scaler.pkl"

FEATURES_BASE = ['dst_port', 'bytes_sent', 'bytes_recv', 'duration_sec', 'packets']


def construir_features(df):
    """Recrea las mismas variables derivadas usadas en el entrenamiento."""
    df = df.copy()
    df['ratio_bytes'] = df['bytes_sent'] / (df['bytes_recv'] + 1)
    df['bytes_por_segundo'] = (df['bytes_sent'] + df['bytes_recv']) / (df['duration_sec'] + 0.01)
    df['paquetes_por_segundo'] = df['packets'] / (df['duration_sec'] + 0.01)
    return df


def main():
    if len(sys.argv) != 2:
        print("Uso: python predecir.py <archivo.csv>")
        sys.exit(1)

    csv_path = sys.argv[1]

    try:
        modelo = joblib.load(MODELO_PATH)
        scaler = joblib.load(SCALER_PATH)
    except FileNotFoundError as e:
        print(f"[ERROR] No se encontró el modelo o el scaler: {e}")
        print("Asegúrate de haber ejecutado el notebook deteccion_anomalias.ipynb primero.")
        sys.exit(1)

    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {csv_path}")
        sys.exit(1)

    df_feat = construir_features(df)

    features_completas = FEATURES_BASE + ['ratio_bytes', 'bytes_por_segundo', 'paquetes_por_segundo']

    columnas_faltantes = [c for c in features_completas if c not in df_feat.columns]
    if columnas_faltantes:
        print(f"[ERROR] Faltan columnas requeridas en el CSV: {columnas_faltantes}")
        sys.exit(1)

    X_nuevo = scaler.transform(df_feat[features_completas])

    predicciones = modelo.predict(X_nuevo)
    scores = modelo.decision_function(X_nuevo)

    df_feat['prediccion'] = predicciones
    df_feat['anomaly_score'] = scores

    anomalias = df_feat[df_feat['prediccion'] == -1].sort_values('anomaly_score')

    print(f"Total de registros analizados: {len(df_feat)}")
    print(f"Anomalías detectadas: {len(anomalias)}\n")

    if len(anomalias) == 0:
        print("No se detectaron anomalías en este archivo.")
    else:
        print("=== REGISTROS CLASIFICADOS COMO ANOMALÍA ===\n")
        columnas_mostrar = ['src_ip', 'dst_ip', 'dst_port', 'protocol',
                             'bytes_sent', 'bytes_recv', 'duration_sec',
                             'packets', 'anomaly_score']
        columnas_disponibles = [c for c in columnas_mostrar if c in anomalias.columns]
        for _, fila in anomalias.iterrows():
            print(f"[ANOMALÍA] score={fila['anomaly_score']:.4f} | " +
                  " | ".join(f"{c}={fila[c]}" for c in columnas_disponibles if c != 'anomaly_score'))


if __name__ == "__main__":
    main()
