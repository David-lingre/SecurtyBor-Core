from flask import Flask, jsonify, request
from flask_cors import CORS
import time

app = Flask(__name__)

# 1. Configuración de CORS restrictivo (Mitigación OWASP: Control de Acceso)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

# 2. Control de Rate Limiting nativo en memoria (Mitigación STRIDE: DoS)
# Estructura: { "IP": [timestamp1, timestamp2, ...] }
request_records = {}
MAX_REQUESTS = 10  # Máximo de peticiones
TIME_WINDOW = 60   # Ventana de tiempo en segundos (1 minuto)

@app.route("/health", methods=["GET"])
def health_check():
    client_ip = request.remote_addr or "127.0.0.1"
    current_time = time.time()
    
    # Limpiar registros antiguos fuera de la ventana de tiempo
    if client_ip in request_records:
        request_records[client_ip] = [t for t in request_records[client_ip] if current_time - t < TIME_WINDOW]
    else:
        request_records[client_ip] = []
        
    # Validar si excede el límite
    if len(request_records[client_ip]) >= MAX_REQUESTS:
        return jsonify({
            "error": "Demasiadas peticiones desde esta IP, intente más tarde."
        }), 429
        
    # Registrar la petición actual
    request_records[client_ip].append(current_time)

    return jsonify({
        "status": "SecurtyBor Core running securely",
        "layer": "1 - Servidor y Defensas Globales (Flask)",
        "protection": "Active"
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)