from fastapi import APIRouter, Query
import secrets

router = APIRouter()

@router.get("/token")
def generate_token(length: int = Query(32, ge=16, le=64, description="Longitud del token en bytes (hex)")):
    token = secrets.token_hex(length)
    return {"token": token}
