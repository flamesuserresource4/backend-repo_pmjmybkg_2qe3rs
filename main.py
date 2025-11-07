import os
from typing import Optional
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from database import db, create_document, get_documents
from schemas import User
from bson.objectid import ObjectId
import hashlib
import secrets

app = FastAPI(title="LandJav API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class RegisterRequest(BaseModel):
    name: str
    password: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None

class RegisterResponse(BaseModel):
    id: str
    name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None

class LoginRequest(BaseModel):
    password: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None

class LoginResponse(BaseModel):
    id: str
    name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None


def _hash_password(password: str, salt: Optional[str] = None):
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100_000)
    return salt, dk.hex()


@app.get("/")
def read_root():
    return {"message": "LandJav backend running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = os.getenv("DATABASE_NAME") or "❌ Not Set"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
                response["connection_status"] = "Connected"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response

@app.post("/auth/register", response_model=RegisterResponse)
def register(payload: RegisterRequest):
    if not payload.email and not payload.phone:
        raise HTTPException(status_code=400, detail="Provide email or phone")
    if payload.email and payload.phone:
        # Optional: allow both, but one unique identifier is enough
        pass

    # Basic uniqueness checks
    criteria = []
    if payload.email:
        criteria.append({"email": payload.email})
    if payload.phone:
        criteria.append({"phone": payload.phone})

    if criteria:
        existing = db["user"].find_one({"$or": criteria})
        if existing:
            raise HTTPException(status_code=409, detail="Account already exists")

    salt, password_hash = _hash_password(payload.password)
    doc = {
        "name": payload.name,
        "email": payload.email,
        "phone": payload.phone,
        "password_hash": password_hash,
        "salt": salt,
        "is_active": True,
    }

    new_id = create_document("user", doc)
    return RegisterResponse(id=new_id, name=payload.name, email=payload.email, phone=payload.phone)

@app.post("/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest):
    if not payload.email and not payload.phone:
        raise HTTPException(status_code=400, detail="Provide email or phone")

    query = {}
    if payload.email:
        query = {"email": payload.email}
    if payload.phone:
        query = {"phone": payload.phone}

    user = db["user"].find_one(query)
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")

    salt = user.get("salt")
    _, check_hash = _hash_password(payload.password, salt)
    if check_hash != user.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return LoginResponse(id=str(user.get("_id")), name=user.get("name"), email=user.get("email"), phone=user.get("phone"))

