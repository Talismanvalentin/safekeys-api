from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field, SecretStr

from app.guards import BruteForceProtector
from app.security import hash_password, verify_password

router = APIRouter()


class HashPasswordRequest(BaseModel):
    password: SecretStr = Field(min_length=12, max_length=128)


class HashPasswordResponse(BaseModel):
    hashed_password: str


class VerifyPasswordRequest(BaseModel):
    password: SecretStr = Field(min_length=12, max_length=128)
    hashed_password: str = Field(min_length=20, max_length=512)


class VerifyPasswordResponse(BaseModel):
    valid: bool


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


@router.post("/hash", response_model=HashPasswordResponse)
def create_password_hash(payload: HashPasswordRequest, request: Request) -> HashPasswordResponse:
    hasher = request.app.state.hasher
    settings = request.app.state.settings
    hashed = hash_password(payload.password.get_secret_value(), settings, hasher)
    return HashPasswordResponse(hashed_password=hashed)


@router.post("/verify", response_model=VerifyPasswordResponse)
def verify_password_hash(payload: VerifyPasswordRequest, request: Request) -> VerifyPasswordResponse:
    hasher = request.app.state.hasher
    settings = request.app.state.settings
    protector: BruteForceProtector = request.app.state.brute_force_protector
    client_ip = _client_ip(request)

    brute_force_state = protector.is_blocked(client_ip)
    if not brute_force_state.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
            headers={"Retry-After": str(brute_force_state.retry_after_seconds)},
        )

    is_valid = verify_password(
        payload.password.get_secret_value(),
        payload.hashed_password,
        settings,
        hasher,
    )

    if not is_valid:
        protector.register_failure(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password or hash.",
        )

    protector.reset(client_ip)
    return VerifyPasswordResponse(valid=True)
