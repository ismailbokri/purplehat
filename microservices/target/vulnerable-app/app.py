import os
import threading
import socket
import subprocess
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from flask import Flask, request, render_template_string

# ==========================================
# Service 1: Vulnerable Web App (Port 8080)
# ==========================================
app = Flask(__name__)

@app.route('/')
def index():
    return """
    <h1>System Admin Portal v0.9</h1>
    <ul>
        <li><a href="/ping">Network Diagnostics (RCE)</a></li>
        <li><a href="/read?file=app.py">Read Logs (LFI)</a></li>
    </ul>
    """

@app.route('/ping', methods=['GET', 'POST'])
def ping():
    # OS Command Injection Vulnerability
    result = ""
    if request.method == 'POST':
        target = request.form.get('ip', '127.0.0.1')
        # Unsafe execution
        try:
            output = subprocess.check_output(f"ping -c 2 {target}", shell=True, stderr=subprocess.STDOUT)
            result = output.decode('utf-8')
        except subprocess.CalledProcessError as e:
            result = e.output.decode('utf-8')
            
    return f"""
    <h3>Ping Tool</h3>
    <form method="POST">
        IP: <input type="text" name="ip" value="127.0.0.1">
        <input type="submit" value="Ping">
    </form>
    <pre>{result}</pre>
    """

@app.route('/read')
def read_file():
    # Local File Inclusion (LFI) Vulnerability
    file_path = request.args.get('file')
    if not file_path:
        return "Please specify a file."
    try:
        with open(file_path, 'r') as f:
            return f"<pre>{f.read()}</pre>"
    except Exception as e:
        return str(e)

def run_flask():
    app.run(host='0.0.0.0', port=8080, threaded=True)

# ==========================================
# Service 2: Open Directory (Port 8081)
# ==========================================
def run_open_directory():
    # Create a dummy open directory with "sensitive" files
    os.makedirs("exposed_data", exist_ok=True)
    with open("exposed_data/config.bak", "w") as f:
        f.write("DB_USER=admin\nDB_PASS=supersecret_legacy_password")
    
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory="exposed_data", **kwargs)
            
    # Suppress normal HTTP logging to keep container logs clean for the agents
    Handler.log_message = lambda self, format, *args: None

    httpd = TCPServer(("0.0.0.0", 8081), Handler)
    httpd.serve_forever()

# ==========================================
# Service 3: Fake Vulnerable Port (Port 2121)
# ==========================================
def run_fake_ftp():
    # Simulates an old service with a banner that matches Exploit-DB entries
    # Target: FreeFloat FTP Server 1.00 (Classic buffer overflow target)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 7121))
    server.listen(5)
    
    while True:
        try:
            client, addr = server.accept()
            # Send the vulnerable banner
            client.send(b"220 FreeFloat Ftp Server (Version 1.00).\r\n")
            client.recv(1024) # Accept dummy USER command
            client.send(b"331 Password required for user.\r\n")
            client.recv(1024) # Accept dummy PASS command
            client.send(b"230 User logged in.\r\n")
            client.close()
        except Exception:
            pass

# ==========================================
# Main Execution
# ==========================================
if __name__ == '__main__':
    print("[*] Starting Vulnerable Services...")
    
    t1 = threading.Thread(target=run_flask, daemon=True)
    t2 = threading.Thread(target=run_open_directory, daemon=True)
    t3 = threading.Thread(target=run_fake_ftp, daemon=True)
    
    t1.start()
    print("[+] Main Web App running on port 8080")
    t2.start()
    print("[+] Open Directory running on port 8081")
    t3.start()
    print("[+] Fake FTP Service running on port 2121")
    
    # Keep the main thread alive
    t1.join()