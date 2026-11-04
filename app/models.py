from pydantic import BaseModel, Field, EmailStr

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Nombre de usuario único")
    email: EmailStr = Field(..., description="Correo electrónico validado")
    password: str = Field(..., min_length=8, description="Contraseña robusta obligatoria")