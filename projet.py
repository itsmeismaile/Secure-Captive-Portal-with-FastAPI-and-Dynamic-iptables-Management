# sudo lsof -i :9090
# sudo kill -9 17799
# sudo iptables -F
# sudo iptables -t nat -F
# uvicorn projet:app  --reload
# uvicorn database:app --reload --port 1010 --host 10.42.0.1

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
import subprocess
import threading
import time
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import IPvAnyAddress,BaseModel
import jwt

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
# Variables de configuration
PORT = 9090  # Port d'écoute du serveur web
IFACE = "wlp2s0"  # Interface protégée
IP_ADDRESS = "10.42.0.1"  # Adresse IP du portail captif
CONNECTION_TIMEOUT = 15  # Temps de connexion en secondes

app = FastAPI(title="Captive Portal")

class IPPayload(BaseModel):
    ip: IPvAnyAddress
    status: str

# Dictionnaire pour suivre les connexions autorisées et leur expiration
authorized_users = {}

# Initialisation des règles IP tables
def setup_iptables():
    print("Configuration initiale des règles iptables")
    subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
    subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
    subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", str(PORT), "-d", IP_ADDRESS, "-j", "ACCEPT"])
    subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-j", "DROP"])
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", IFACE, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{IP_ADDRESS}:{PORT}"])
    print("Règles iptables configurées")

# Autoriser un utilisateur pendant un temps limité
def authorize_user(remote_ip: str):
    print(f"Nouvelle autorisation de {remote_ip}")
    subprocess.call(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-s", remote_ip, "-j", "ACCEPT"])
    subprocess.call(["iptables", "-I", "FORWARD", "-s", remote_ip, "-j", "ACCEPT"])
    authorized_users[remote_ip] = time.time() + CONNECTION_TIMEOUT

# Révoquer une autorisation
def revoke_user(remote_ip: str):
    print(f"Révocation de l'autorisation pour {remote_ip}")
    subprocess.call(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", remote_ip, "-j", "ACCEPT"])
    subprocess.call(["iptables", "-D", "FORWARD", "-s", remote_ip, "-j", "ACCEPT"])
    if remote_ip in authorized_users:
        del authorized_users[remote_ip]

# Tâche en arrière-plan pour surveiller les expirations
def monitor_authorizations():
    while True:
        current_time = time.time()
        expired_users = [ip for ip, expiry in authorized_users.items() if expiry < current_time]
        for ip in expired_users:
            revoke_user(ip)
        time.sleep(2)  # Vérifier toutes les 5 secondes

# Page de redirection
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def redirect():
    url = f"http://{IP_ADDRESS}:{PORT}/login"
    return templates.TemplateResponse(
        name="redirect.html", context={"url": url}
    )

# Page de connexion
@app.get("/login", response_class=HTMLResponse)
async def login_page(request : Request):
    return templates.TemplateResponse("login.html", {"request": request})

# Gestion du formulaire de connexion
@app.post("/permission", response_class=HTMLResponse)
async def handle_login(response : str,request : Request):
    payload = jwt.decode(response, SECRET_KEY, algorithms=[ALGORITHM])
    if payload.get("status") == "True":
        authorize_user(payload.get("ip"))
        return f"""
        <html>
        <body>
            <b>You are now authorized for {CONNECTION_TIMEOUT // 60} minute(s). Navigate to any URL.</b>
        </body>
        </html>
        """
    else:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid credentials. Try again."}
        )

@app.get("/{path:path}", response_class=HTMLResponse)
async def catch_all(path: str, request: Request):
    if path == "login":
        return templates.TemplateResponse("login.html", {"request": request})
    else:
        url = f"http://{IP_ADDRESS}:{PORT}/login"
        return templates.TemplateResponse(
            name="redirect.html", context={"url": url, "request": request}
        )

# Démarrer la surveillance des autorisations
threading.Thread(target=monitor_authorizations, daemon=True).start()

# Lancement de l'application
if __name__ == "__main__":
    import uvicorn

    setup_iptables()
    print(f"Lancement du serveur sur http://{IP_ADDRESS}:{PORT}")
    uvicorn.run(app, host=IP_ADDRESS, port=PORT)
