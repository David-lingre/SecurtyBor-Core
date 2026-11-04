from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Configuración de Rate Limiting (Mitigación DoS - STRIDE)
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="SecurtyBor Core",
    description="Backend de seguridad defensiva con FastAPI, OWASP y STRIDE",
    version="1.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Restrictivo (Mitigación OWASP)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Ajustar en producción
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.get("/health")
@limiter.limit("20/minute")
def health_check(request: Request):
    return {
        "status": "SecurtyBor Core running securely",
        "protection": "Active",
        "framework": "FastAPI"
    }