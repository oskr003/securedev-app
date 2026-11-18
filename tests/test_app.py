"""@file test_app.py
@brief Pruebas unitarias y de seguridad para la aplicación Flask SecureDev.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app


def test_health_endpoint():
    """Verifica que /health responda HTTP 200 y status ok."""
    client = app.test_client()
    res = client.get("/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"


def test_index_endpoint():
    """Verifica que la ruta raíz responda HTTP 200."""
    client = app.test_client()
    res = client.get("/")
    assert res.status_code == 200
    assert b"SecureDev App" in res.data


def test_hello_endpoint():
    """Verifica que /hello devuelva el saludo esperado."""
    client = app.test_client()
    res = client.get("/hello?name=Oscar")
    assert res.status_code == 200
    assert b"Oscar" in res.data


def test_hello_xss_escaped():
    """Verifica que /hello escape payloads XSS."""
    client = app.test_client()
    res = client.get("/hello?name=<script>alert(1)</script>")
    assert res.status_code == 200
    assert b"<script>" not in res.data
    assert b"&lt;script&gt;" in res.data


def test_security_headers():
    """Verifica la presencia de cabeceras de seguridad HTTP."""
    client = app.test_client()
    res = client.get("/")
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")
