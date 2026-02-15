from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_app_metadata():
    assert app.title == "SafeKeys API"


def test_generate_password_endpoint():
    response = client.get("/generate/password", params={"length": 16})
    assert response.status_code == 200
    payload = response.json()
    assert "password" in payload
    assert len(payload["password"]) == 16


def test_generate_password_validation():
    response = client.get("/generate/password", params={"length": 8})
    assert response.status_code == 422


def test_hash_and_verify_password():
    password = "StrongPassword123!"
    hash_response = client.post("/security/hash", json={"password": password})
    assert hash_response.status_code == 200

    hashed_password = hash_response.json()["hashed_password"]
    assert hashed_password.startswith("$argon2")

    verify_response = client.post(
        "/security/verify",
        json={"password": password, "hashed_password": hashed_password},
    )
    assert verify_response.status_code == 200
    assert verify_response.json() == {"valid": True}


def test_verify_password_invalid():
    password = "StrongPassword123!"
    hash_response = client.post("/security/hash", json={"password": password})
    hashed_password = hash_response.json()["hashed_password"]

    verify_response = client.post(
        "/security/verify",
        json={"password": "WrongPassword123!", "hashed_password": hashed_password},
    )
    assert verify_response.status_code == 401
