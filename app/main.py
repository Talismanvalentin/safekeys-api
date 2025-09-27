from fastapi import FastAPI
from app.routes import password, token



app = FastAPI(
    title="SafeKeys API",
    description="API para generar contraseñas y tokens seguros",
    version="1.0.0"
)

app.include_router(password.router, prefix="/generate", tags=["Password"])
app.include_router(token.router, prefix="/generate", tags=["Token"])
