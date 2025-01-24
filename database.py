 # PRAGMA table_info(nom_de_la_table);
from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi import FastAPI, HTTPException, Depends, Form, Request
from sqlalchemy import create_engine, Column, Integer, String, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel, IPvAnyAddress
import requests
from fastapi.responses import RedirectResponse
import jwt

# Configuration
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"

DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modèles Pydantic
class IPPayload(BaseModel):
    ip: IPvAnyAddress
    status: str


# Modèle de base de données
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    user_name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    __table_args__ = (UniqueConstraint("email", name="unique_email"),)


# Création de la base de données
Base.metadata.create_all(bind=engine)

# FastAPI
app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Utilitaires
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)
print(get_password_hash("123"))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Endpoints
@app.post("/users/")
def read_user(
    request: Request,
    user_name: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    """
    Authentifie un utilisateur et redirige entièrement vers /permission.
    """
    # Recherche de l'utilisateur dans la base de données
    user = db.query(User).filter(User.user_name == user_name).first()

    # Vérification des informations utilisateur
    if user is None or not verify_password(password, user.hashed_password):
        # Préparation des données pour le serveur de permissions
        payload = {
            "ip": request.client.host,
            "status": "False",
            "tm": datetime.now(timezone.utc).isoformat()
        }
        encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        # Redirection vers /permission
        return RedirectResponse(
            url=f"http://10.42.0.1:9090/permission?response={encoded_jwt}",
            status_code=307
        )

    # Préparation des données pour le serveur de permissions
    payload = {
        "ip": request.client.host,
        "status": "True",
        "tm": datetime.now(timezone.utc).isoformat()
    }
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    # Redirection vers /permission
    return RedirectResponse(
        url=f"http://10.42.0.1:9090/permission?response={encoded_jwt}",
        status_code=307
    )

# Lancement du serveur
if __name__ == "__main__":
    import uvicorn

    print("Lancement du serveur sur http://10.42.0.1:1010")
    uvicorn.run(app, host="10.42.0.1", port=1010)
