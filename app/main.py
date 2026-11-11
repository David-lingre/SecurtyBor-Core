from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import time

app = Flask(__name__)

# Configuración de clave secreta para la firma de tokens
app.config["SECRET_KEY"] = "securtybor-core-super-secure-key-2026"
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# ==========================================
# CAPA 1: DEFENSAS GLOBALES Y CONTROL DE RED
# ==========================================
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

request_records = {}
MAX_REQUESTS = 20  
TIME_WINDOW = 60   

@app.before_request
def limit_traffic():
    """Middleware global que protege todos los endpoints contra DoS y Fuerza Bruta."""
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
        
    hashed_password = generate_password_hash(password)
    users_db[username] = hashed_password
    
    return jsonify({"message": f"Usuario '{username}' registrado exitosamente."}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Faltan credenciales"}), 400
        
    username = data["username"]
    password = data["password"]
    generic_error = {"error": "Credenciales inválidas"}
    
    if username not in users_db:
        return jsonify(generic_error), 401
        
    if check_password_hash(users_db[username], password):
        # CAPA 3: Generación de token firmado digitalmente con expiración (1 hora)
        token = serializer.dumps(username)
        return jsonify({
            "message": "Autenticación exitosa",
            "token": token,
            "token_type": "Bearer",
            "expires_in": "3600 seconds"
        }), 200
        
    return jsonify(generic_error), 401


# ==========================================
# CAPA 3: AUTORIZACIÓN Y RECURSOS PROTEGIDOS
# ==========================================
@app.route("/protected-resource", methods=["GET"])
def protected_resource():
    auth_header = request.headers.get("Authorization")
    
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Token de autorización ausente o malformado"}), 401
        
    token = auth_header.split(" ")[1]
    
    try:
        username = serializer.loads(token, max_age=3600)
    except SignatureExpired:
        return jsonify({"error": "El token ha expirado. Por favor inicie sesión nuevamente."}), 401
    except BadSignature:
        return jsonify({"error": "Token inválido o manipulado."}), 401

    return jsonify({
        "status": "Acceso concedido al recurso restringido",
        "authenticated_user": username,
        "layer": "3 - Autorización mediante Tokens Firmados",
        "protection": "Active (Anti-Elevation of Privilege)"
    })


# ==========================================
# ENDPOINTS DE MONITOREO
# ==========================================
@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "SecurtyBor Core running securely",
        "layers_active": "Capa 1 (Anti-DoS/CORS), Capa 2 (Hashing/Spoofing), Capa 3 (Tokens Firmados)",
        "protection": "Fully Operational"
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)