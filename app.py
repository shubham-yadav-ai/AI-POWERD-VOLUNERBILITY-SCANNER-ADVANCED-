from flask import Flask, request, jsonify
from flask_cors import CORS
import socket
import requests

app = Flask(__name__)
CORS(app)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    domain = data.get('domain', '')
    
    # Basic port check
    open_ports = []
    for port in [80, 443, 22, 21, 3306]:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((domain, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    
    # Header check
    headers_ok = True
    try:
        r = requests.get(f'http://{domain}', timeout=5)
        headers_ok = 'x-frame-options' in r.headers or 'content-security-policy' in r.headers
        ssl_ok = True
    except:
        ssl_ok = False
    
    return jsonify({
        'domain': domain,
        'open_ports': open_ports,
        'headers_ok': headers_ok,
        'ssl_ok': ssl_ok,
        'risk': round(min(9.9, len(open_ports) * 0.8 + (0 if headers_ok else 1.5)), 1)
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)