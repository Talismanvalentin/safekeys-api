from secrets import compare_digest
from time import perf_counter

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from app.config import load_settings
from app.guards import BruteForceProtector, SlidingWindowRateLimiter
from app.logging_utils import configure_logging, log_event
from app.routes import password, security, token
from app.security import build_hasher


settings = load_settings()
logger = configure_logging()

app = FastAPI(
    title="SafeKeys API",
    description="API for secure password and token operations",
    version="1.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.state.settings = settings
app.state.hasher = build_hasher()
app.state.rate_limiter = SlidingWindowRateLimiter(
    max_requests=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window_seconds,
)
app.state.brute_force_protector = BruteForceProtector(
    max_failures=settings.brute_force_max_failures,
    window_seconds=settings.brute_force_window_seconds,
    lock_seconds=settings.brute_force_lock_seconds,
)
docs_basic_auth = HTTPBasic()


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    start = perf_counter()
    client_ip = _client_ip(request)
    rate_limit = request.app.state.rate_limiter.check(client_ip)

    if not rate_limit.allowed:
        log_event(
            logger,
            "rate_limit_exceeded",
            method=request.method,
            path=request.url.path,
            client_ip=client_ip,
            retry_after=rate_limit.retry_after_seconds,
        )
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Try again later."},
            headers={"Retry-After": str(rate_limit.retry_after_seconds)},
        )

    response = await call_next(request)
    duration_ms = round((perf_counter() - start) * 1000, 2)
    log_event(
        logger,
        "http_request",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=duration_ms,
        client_ip=client_ip,
    )
    return response


if not settings.pepper:
    log_event(logger, "security_warning", detail="SAFEKEYS_PEPPER is empty; set it in production.")


def require_docs_auth(credentials: HTTPBasicCredentials = Depends(docs_basic_auth)) -> None:
    valid_username = compare_digest(credentials.username, settings.docs_username)
    valid_password = compare_digest(credentials.password, settings.docs_password)
    if not (valid_username and valid_password):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )


@app.get("/private/openapi.json", include_in_schema=False, dependencies=[Depends(require_docs_auth)])
def private_openapi():
    return app.openapi()


@app.get("/private/docs", include_in_schema=False, dependencies=[Depends(require_docs_auth)])
def private_docs():
    return get_swagger_ui_html(
        openapi_url="/private/openapi.json",
        title="SafeKeys API - Private Docs",
    )


app.include_router(password.router, prefix="/generate", tags=["Password"])
app.include_router(token.router, prefix="/generate", tags=["Token"])
app.include_router(security.router, prefix="/security", tags=["Security"])
