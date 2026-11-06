from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import time

app = Flask(__name__)

# ==========================================
# CAPA 1: DEFENSAS GLOBALES Y CONTROL DE RED
# ==========================================
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

request_records = {}
MAX_REQUESTS = 20  # Límite ajustado para permitir pruebas de login/registro
TIME_WINDOW = 60

@app.before_request
def limit_traffic():
    """Middleware que protege TODOS los endpoints contra DoS y Fuerza Bruta."""
    client_ip = request.remote_addr or "127.0.0.1"
    current_time = time.time()
    
    if client_ip in request_records:
        request_records[client_ip] = [t for t in request_records[client_ip] if current_time - t < TIME_WINDOW]
    else:
        request_records[client_ip] = []
        
    if len(request_records[client_ip]) >= MAX_REQUESTS:
        return jsonify({"error": "Rate limit excedido. Bloqueo temporal de seguridad."}), 429
        
    request_records[client_ip].append(current_time)


# ==========================================
# CAPA 2: AUTENTICACIÓN Y HASHING (STRIDE: Spoofing)
# ==========================================
# Base de datos en memoria (diccionario) para mantener la arquitectura ágil en esta fase
users_db = {}

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Faltan credenciales"}), 400
        
    username = data["username"]
    password = data["password"]
    
    if username in users_db:
        return jsonify({"error": "Conflicto: El usuario ya existe"}), 409
        
    # Cifrado unidireccional (hashing) de la contraseña antes de guardarla
    hashed_password = generate_password_hash(password)
    users_db[username] = hashed_password
    
    return jsonify({"message": f"Usuario '{username}' registrado con seguridad."}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Faltan credenciales"}), 400
        
    username = data["username"]
    password = data["password"]
    
    # Práctica OWASP: Mensaje de error genérico para no revelar si el usuario existe o no
    generic_error = {"error": "Credenciales inválidas"}
    
    if username not in users_db:
        return jsonify(generic_error), 401
        
    # Verificación segura del hash contra la contraseña en texto plano recibida
    if check_password_hash(users_db[username], password):
        # En la Capa 3 cambiaremos este string por un JWT real firmado
        return jsonify({"message": "Autenticación exitosa", "token": "TBD_JWT_CAPA_3"}), 200
        
    return jsonify(generic_error), 401


# ==========================================
# ENDPOINTS DE MONITOREO
# ==========================================
@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "SecurtyBor Core running securely",
        "layer": "2 - Autenticación y Hashing",
        "protection": "Active (Anti-DoS & Anti-Spoofing)"
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
