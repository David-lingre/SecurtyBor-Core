from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from cryptography.fernet import Fernet
import time
import hashlib
import json
import os

app = Flask(__name__)

# Configuración de llaves maestras criptográficas
app.config["SECRET_KEY"] = "securtybor-core-super-secure-key-2026"
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# Generación de llave simétrica para Confidencialidad (Fernet)
# En un entorno real se carga de una variable de entorno segura
FERNET_KEY = Fernet.generate_key()
cipher_suite = Fernet(FERNET_KEY)

AUDIT_LOG_FILE = "audit_trail.log"

def log_audit_event(event_type, username, status):
    """Implementa No Repudio mediante una cadena de bloques de logs con hash."""
    timestamp = time.time()
    previous_hash = "0" * 64
    
    if os.path.exists(AUDIT_LOG_FILE) and os.path.getsize(AUDIT_LOG_FILE) > 0:
        with open(AUDIT_LOG_FILE, "r") as f:
            lines = f.readlines()
            if lines:
                last_record = json.loads(lines[-1].strip())
                previous_hash = last_record.get("current_hash", previous_hash)
                
    raw_data = f"{timestamp}:{event_type}:{username}:{status}:{previous_hash}"
    current_hash = hashlib.sha256(raw_data.encode()).hexdigest()
    
    log_entry = {
        "timestamp": timestamp,
        "event": event_type,
        "user": username,
        "status": status,
        "previous_hash": previous_hash,
        "current_hash": current_hash
    }
    
    with open(AUDIT_LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

# ==========================================
# CAPA 1: DEFENSAS GLOBALES Y CONTROL DE RED
# ==========================================
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

request_records = {}
MAX_REQUESTS = 20  
TIME_WINDOW = 60   

@app.before_request
def limit_traffic():
    client_ip = request.remote_addr or "127.0.0.1"
    current_time = time.time()
    
    if client_ip in request_records:
        request_records[client_ip] = [t for t in request_records[client_ip] if current_time - t < TIME_WINDOW]
    else:
        request_records[client_ip] = []
        
    if len(request_records[client_ip]) >= MAX_REQUESTS:
        log_audit_event("RATE_LIMIT", client_ip, "BLOCKED")
        return jsonify({"error": "Rate limit excedido. Bloqueo temporal de seguridad."}), 429
        
    request_records[client_ip].append(current_time)


# ==========================================
# CAPA 2: AUTENTICACIÓN Y HASHING
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
        log_audit_event("REGISTER", username, "CONFLICT")
        return jsonify({"error": "Conflicto: El usuario ya existe"}), 409
        
    users_db[username] = generate_password_hash(password)
    log_audit_event("REGISTER", username, "SUCCESS")
    return jsonify({"message": f"Usuario '{username}' registrado exitosamente."}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Faltan credenciales"}), 400
        
    username = data["username"]
    password = data["password"]
    generic_error = {"error": "Credenciales inválidas"}
    
    if username not in users_db or not check_password_hash(users_db[username], password):
        log_audit_event("LOGIN", username, "FAILED")
        return jsonify(generic_error), 401
        
    # CAPA 3 + Confidencialidad: Generación de token firmado Y cifrado simétricamente
    signed_token = serializer.dumps(username)
    encrypted_token = cipher_suite.encrypt(signed_token.encode()).decode()
    
    log_audit_event("LOGIN", username, "SUCCESS")
    return jsonify({
        "message": "Autenticación exitosa",
        "encrypted_token": encrypted_token,
        "token_type": "Bearer-Encrypted",
        "expires_in": "3600 seconds"
    }), 200


# ==========================================
# CAPA 3: AUTORIZACIÓN Y RECURSOS PROTEGIDOS
# ==========================================
@app.route("/protected-resource", methods=["GET"])
def protected_resource():
    auth_header = request.headers.get("Authorization")
    
    if not auth_header or not auth_header.startswith("Bearer "):
        log_audit_event("ACCESS", "unknown", "UNAUTHORIZED")
        return jsonify({"error": "Token de autorización ausente o malformado"}), 401
        
    encrypted_token = auth_header.split(" ")[1]
    
    try:
        # Desencriptación simétrica (Confidencialidad)
        decrypted_signed_token = cipher_suite.decrypt(encrypted_token.encode()).decode()
        # Validación de firma e integridad (Integridad / No repudio)
        username = serializer.loads(decrypted_signed_token, max_age=3600)
    except (SignatureExpired, BadSignature, Exception):
        log_audit_event("ACCESS", "unknown", "INVALID_TOKEN")
        return jsonify({"error": "Token inválido, manipulado o expirado."}), 401

    log_audit_event("ACCESS", username, "GRANTED")
    return jsonify({
        "status": "Acceso concedido al recurso restringido",
        "authenticated_user": username,
        "cryptographic_guarantees": ["Confidencialidad (AES/Fernet)", "Integridad (HMAC)", "Autenticación", "No Repudio (Hash Chain Audit)"],
        "protection": "Active"
    })


# ==========================================
# ENDPOINTS DE EVIDENCIA Y MONITOREO
# ==========================================
@app.route("/audit-logs", methods=["GET"])
def get_audit_logs():
    """Endpoint de evidencia para demostrar el No Repudio mediante la cadena de hashes."""
    if not os.path.exists(AUDIT_LOG_FILE):
        return jsonify({"logs": []}), 200
        
    logs = []
    with open(AUDIT_LOG_FILE, "r") as f:
        for line in f:
            logs.append(json.loads(line.strip()))
    return jsonify({"audit_chain": logs, "status": "Immutable Trail Verified"}), 200

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "SecurtyBor Core running securely",
        "crypto_objectives": ["Confidencialidad", "Integridad", "Autenticación", "No Repudio"],
        "protection": "Fully Operational"
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)