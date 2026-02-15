# SafeKeys API

API built with FastAPI for secure password and token operations.

## Security features

- Strong hashing with Argon2 (`/security/hash` and `/security/verify`)
- Correct salting through Argon2 (automatic unique salt per hash)
- Optional pepper via environment variable (`SAFEKEYS_PEPPER`)
- Global rate limiting by IP (sliding window)
- Brute force protection for password verification endpoint
- Structured JSON logging
- Strict request validation with Pydantic constraints
- Secrets managed via environment variables

## Requirements

- Python 3.11+
- Dependencies listed in `requirements.txt`

## Local setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Docs:

- Private Swagger UI: `http://127.0.0.1:8000/private/docs`
- Private OpenAPI: `http://127.0.0.1:8000/private/openapi.json`

## Environment variables

```bash
export SAFEKEYS_ENV=development
export SAFEKEYS_PEPPER="change-this-in-production"
export SAFEKEYS_DOCS_USERNAME="admin"
export SAFEKEYS_DOCS_PASSWORD="change-me"
export SAFEKEYS_RATE_LIMIT_REQUESTS=60
export SAFEKEYS_RATE_LIMIT_WINDOW_SECONDS=60
export SAFEKEYS_BRUTE_FORCE_MAX_FAILURES=5
export SAFEKEYS_BRUTE_FORCE_WINDOW_SECONDS=300
export SAFEKEYS_BRUTE_FORCE_LOCK_SECONDS=600
```

Public docs are disabled (`/docs` and `/openapi.json`).
Use Basic Auth credentials configured above for private docs endpoints.

## Endpoints

### Generate password

`GET /generate/password?length=16`

- Length range: `12..128`
- Enforces complexity in generated password:
  - lowercase
  - uppercase
  - digit
  - symbol

### Generate token

`GET /generate/token?length=32`

- Length range: `16..64` (bytes for `token_hex`)

### Hash password

`POST /security/hash`

Request:

```json
{
  "password": "StrongPassword123!"
}
```

Response:

```json
{
  "hashed_password": "$argon2id$..."
}
```

### Verify password

`POST /security/verify`

Request:

```json
{
  "password": "StrongPassword123!",
  "hashed_password": "$argon2id$..."
}
```

Success response:

```json
{
  "valid": true
}
```

Invalid password/hash returns `401`.
Too many failed attempts returns `429` with `Retry-After`.

## How it works

1. Generate a password or token
- `GET /generate/password?length=16`
- `GET /generate/token?length=32`

2. Hash a user password before storing it
- Send plaintext to `POST /security/hash`
- The API returns an Argon2 hash string (includes algorithm params + unique salt)

3. Verify password at login
- Send plaintext + stored hash to `POST /security/verify`
- If valid: `200 {"valid": true}`
- If invalid: `401`
- After repeated failures from same IP: `429` (temporary lock)

4. Docs access (private only)
- Public docs are disabled.
- Access docs with Basic Auth:

```bash
curl -u "$SAFEKEYS_DOCS_USERNAME:$SAFEKEYS_DOCS_PASSWORD" \
  http://127.0.0.1:8000/private/openapi.json
```

### Example flow (curl)

Generate a password:

```bash
curl "http://127.0.0.1:8000/generate/password?length=16"
```

Hash a password:

```bash
curl -X POST "http://127.0.0.1:8000/security/hash" \
  -H "Content-Type: application/json" \
  -d '{"password":"StrongPassword123!"}'
```

Verify a password:

```bash
curl -X POST "http://127.0.0.1:8000/security/verify" \
  -H "Content-Type: application/json" \
  -d '{"password":"StrongPassword123!","hashed_password":"$argon2id$..."}'
```

## Tests

```bash
. .venv/bin/activate
pytest -q
```
