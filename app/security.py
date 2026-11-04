from passlib.context import CryptContext

# Contexto con Argon2 para mitigación de Spoofing (STRIDE)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    """Genera un hash seguro con Argon2 para contraseñas"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica credenciales de forma segura contra ataques de tiempo"""
    return pwd_context.verify(plain_password, hashed_password)