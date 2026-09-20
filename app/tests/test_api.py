from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_unauthorized_target_rejected():
    """Kapsam dışı IP verildiğinde 422 dönmeli."""
    response = client.post("/scan", json={"target": "8.8.8.8", "profile": "fast"})
    assert response.status_code == 422
    assert "yetkili laboratuvar kapsamı dışındadır" in response.text

def test_invalid_ip_format():
    """Bozuk formatta IP verildiğinde 422 dönmeli."""
    response = client.post("/scan", json={"target": "999.999.999.999", "profile": "fast"})
    assert response.status_code == 422

def test_valid_scan_trigger():
    """İzinli hedef verildiğinde 202 Accepted ve task_id dönmeli."""
    response = client.post("/scan", json={"target": "127.0.0.1", "profile": "fast"})
    assert response.status_code == 202
    data = response.json()
    assert "task_id" in data
    assert data["status"] == "ACCEPTED"