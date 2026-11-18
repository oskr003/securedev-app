"""@file app.py
@brief Aplicación web Flask de SecureDev (versión inicial vulnerable para auditoría DevSecOps).
@details Expone endpoints básicos, saludo dinámico vulnerable a XSS reflejado y métricas Prometheus.
"""

import os
import time
from flask import Flask, request, jsonify, Response
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

# VULNERABILIDAD (CWE-798): Secreto hardcodeado en código fuente (Bandit B105)
SECRET_KEY = "super-secret-hardcoded-key-securedev"
app.config["SECRET_KEY"] = SECRET_KEY

# Métricas para Prometheus / Grafana
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total de peticiones HTTP recibidas",
    ["method", "endpoint", "status"],
)
HTTP_REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "Latencia de peticiones HTTP en segundos",
    ["endpoint"],
)


@app.before_request
def start_timer():
    """@brief Registra el timestamp de inicio de cada petición."""
    request._start_time = time.time()


@app.after_request
def record_metrics(response):
    """@brief Registra métricas de Prometheus tras procesar cada petición."""
    latency = time.time() - getattr(request, "_start_time", time.time())
    endpoint = request.path
    HTTP_REQUESTS_TOTAL.labels(
        method=request.method,
        endpoint=endpoint,
        status=str(response.status_code),
    ).inc()
    HTTP_REQUEST_LATENCY.labels(endpoint=endpoint).observe(latency)
    return response


@app.route("/")
def index():
    """@brief Endpoint raíz de bienvenida.
    @return Mensaje HTML de estado de la aplicación.
    """
    return "<h1>SecureDev App - Entorno DevSecOps</h1><p>Prueba /hello?name=Estudiante</p>"


@app.route("/hello")
def hello():
    """@brief Endpoint de saludo personalizado.
    @details VULNERABILIDAD (CWE-79): XSS reflejado al concatenar el parámetro 'name' sin sanitización.
    @return HTML con el saludo al usuario.
    """
    name = request.args.get("name", "Invitado")
    # VULNERABILIDAD: Concatenación directa sin escape (XSS reflejado)
    return f"<h2>Hola, {name}!</h2>"


@app.route("/health")
def health():
    """@brief Endpoint de verificación de salud del servicio.
    @return JSON con estado 'ok'.
    """
    return jsonify({"status": "ok", "service": "securedev-app"}), 200


@app.route("/metrics")
def metrics():
    """@brief Expone métricas en formato Prometheus.
    @return Respuesta en texto plano con métricas recolectadas.
    """
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    # VULNERABILIDAD (CWE-94 / Bandit B201): debug=True expuesto en producción
    app.run(host="0.0.0.0", port=5000, debug=True)
