"""@file app.py
@brief Aplicación web Flask de SecureDev (versión mitigada y segura).
@details Implementa escape contra XSS, gestión segura de secretos, cabeceras HTTP de seguridad y métricas Prometheus.
"""

import os
import time
from flask import Flask, request, jsonify, Response
from markupsafe import escape
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

# MITIGACIÓN (CWE-798): Obtener secreto desde variable de entorno o generar clave efímera segura
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(24).hex()

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
def apply_security_and_metrics(response):
    """@brief Aplica cabeceras de seguridad HTTP y registra métricas de Prometheus."""
    # MITIGACIÓN (OWASP ZAP): Cabeceras de seguridad recomendadas
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"

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
    return "<h1>SecureDev App - Entorno DevSecOps Seguro</h1><p>Prueba /hello?name=Estudiante</p>"


@app.route("/hello")
def hello():
    """@brief Endpoint de saludo personalizado protegido contra XSS.
    @details MITIGACIÓN (CWE-79): Se utiliza markupsafe.escape para neutralizar caracteres HTML/JS.
    @return HTML seguro con el saludo al usuario.
    """
    name = escape(request.args.get("name", "Invitado"))
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
    # MITIGACIÓN (CWE-94 / Bandit B201 & B104): debug desactivado y host configurable por entorno
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    app.run(host=host, port=5000, debug=False)
