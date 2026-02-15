import secrets
import string

from fastapi import APIRouter, Query

router = APIRouter()


@router.get("/password")
def generate_password(length: int = Query(16, ge=12, le=128, description="Password length")):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}:,.?"

    all_chars = lowercase + uppercase + digits + symbols
    required = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    remaining = [secrets.choice(all_chars) for _ in range(length - len(required))]
    raw_password = required + remaining
    secrets.SystemRandom().shuffle(raw_password)
    password = "".join(raw_password)
    return {"password": password}
