from fastapi import APIRouter, Query
import secrets, string

router = APIRouter()

@router.get("/password")
def generate_password(length: int = Query(16, ge=8, le=128, description="Longitud de la contraseña")):
    charset = string.ascii_letters + string.digits + "!@#$%^&*()"
    password = ''.join(secrets.choice(charset) for _ in range(length))
    return {"password": password}
