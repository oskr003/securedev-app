"""@file test_app.py
@brief Pruebas unitarias básicas para la aplicación Flask SecureDev.
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
