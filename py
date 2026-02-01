
from datetime import datetime, timedelta
from typing import Optional
import os
import secrets

from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import EmailStr, BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select
from passlib.context import CryptContext
from jose import jwt, JWTError


JWT_SECRET = os.getenv("JWT_SECRET", "change_this_secret_for_prod")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
VERIFICATION_TOKEN_EXPIRE_HOURS = 24
PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")

DATABASE_URL = "sqlite:///./auth_demo.db"
engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})

app = FastAPI(title="Auth Demo")


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: EmailStr = Field(index=True, unique=True)
    password_hash: str
    is_active: bool = True
    is_verified: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)

class RefreshToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token: str = Field(index=True, unique=True)
    user_id: int = Field(foreign_key="user.id")
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)

SQLModel.metadata.create_all(engine)

class RegisterIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class UserOut(BaseModel):
    id: int
    email: EmailStr
    is_verified: bool


def hash_password(password: str) -> str:
    return PWD_CONTEXT.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return PWD_CONTEXT.verify(plain, hashed)

def create_access_token(*, sub: int, expires_delta: Optional[timedelta] = None):
    to_encode = {"sub": str(sub), "type": "access"}
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": int(expire.timestamp())})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

def create_verification_token(*, sub: int, purpose: str = "verify", expires_delta: Optional[timedelta] = None):
    to_encode = {"sub": str(sub), "type": purpose}
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=VERIFICATION_TOKEN_EXPIRE_HOURS))
    to_encode.update({"exp": int(expire.timestamp())})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload
    except JWTError:
        return None

def create_refresh_token():
    return secrets.token_urlsafe(64)


def get_user_by_email(session: Session, email: str) -> Optional[User]:
    statement = select(User).where(User.email == email)
    return session.exec(statement).first()

def get_user_by_id(session: Session, user_id: int) -> Optional[User]:
    statement = select(User).where(User.id == user_id)
    return session.exec(statement).first()

# --- Dependencies ---
def get_db():
    with Session(engine) as session:
        yield session

def get_current_user(token: str = Depends(lambda: None), db: Session = Depends(get_db)):
  
    raise HTTPException(status_code=500, detail="Internal dependency used incorrectly")

from fastapi import Header
async def get_current_user_token(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authorization")
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user_id = int(payload.get("sub"))
    user = get_user_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user
@app.post("/api/auth/register", status_code=201)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if get_user_by_email(db, data.email):
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(email=data.email, password_hash=hash_password(data.password), is_verified=False)
    db.add(user)
    db.commit()
    db.refresh(user)

    
    token = create_verification_token(sub=user.id, purpose="verify")
    verify_link = f"http://localhost:8000/api/auth/verify-email?token={token}"

    print(f"[verification link] {verify_link}")

    return {"message": "Registered. Check console for verification link (demo)."}

@app.get("/api/auth/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    payload = decode_token(token)
    if not payload or payload.get("type") != "verify":
        raise HTTPException(status_code=400, detail="Invalid token")
    user_id = int(payload.get("sub"))
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_verified:
        return {"message": "Already verified"}
    user.is_verified = True
    db.add(user)
    db.commit()
    return {"message": "Email verified. You can now log in."}

@app.post("/api/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    
    user = get_user_by_email(db, form.username)
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    access_token = create_access_token(sub=user.id)

    refresh_token = create_refresh_token()
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    rt = RefreshToken(token=refresh_token, user_id=user.id, expires_at=expires_at)
    db.add(rt)
    db.commit()

    return TokenOut(access_token=access_token, refresh_token=refresh_token, expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60)

@app.post("/api/auth/refresh", response_model=TokenOut)
def refresh(refresh_token: str = Body(...), db: Session = Depends(get_db)):
    statement = select(RefreshToken).where(RefreshToken.token == refresh_token)
    rt = db.exec(statement).first()
    if not rt or rt.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Invalid refresh token")

  
    db.delete(rt)
    db.commit()

    new_refresh = create_refresh_token()
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    new_rt = RefreshToken(token=new_refresh, user_id=rt.user_id, expires_at=expires_at)
    db.add(new_rt)
    db.commit()

    user = get_user_by_id(db, rt.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    access_token = create_access_token(sub=user.id)
    return TokenOut(access_token=access_token, refresh_token=new_refresh, expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60)

@app.post("/api/auth/logout")
def logout(refresh_token: str = Body(...), db: Session = Depends(get_db)):
    statement = select(RefreshToken).where(RefreshToken.token == refresh_token)
    rt = db.exec(statement).first()
    if rt:
        db.delete(rt)
        db.commit()
    return {"message": "Logged out (refresh token revoked if it existed)."}

@app.post("/api/auth/request-password-reset")
def request_password_reset(email: EmailStr = Body(...), db: Session = Depends(get_db)):
    user = get_user_by_email(db, email)
    if not user:
      
        return {"message": "If an account exists, a reset link was sent (demo console)."}
    token = create_verification_token(sub=user.id, purpose="reset", expires_delta=timedelta(hours=2))
    reset_link = f"http://localhost:8000/api/auth/reset-password?token={token}"
    print(f"[password reset link] {reset_link}")
    return {"message": "If an account exists, a reset link was sent (demo console)."}

@app.post("/api/auth/reset-password")
def reset_password(token: str = Body(...), new_password: str = Body(..., min_length=6), db: Session = Depends(get_db)):
    payload = decode_token(token)
    if not payload or payload.get("type") != "reset":
        raise HTTPException(status_code=400, detail="Invalid token")
    user_id = int(payload.get("sub"))
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.password_hash = hash_password(new_password)
    
    statement = select(RefreshToken).where(RefreshToken.user_id == user.id)
    tokens = db.exec(statement).all()
    for t in tokens:
        db.delete(t)
    db.add(user)
    db.commit()
    return {"message": "Password reset successful; all sessions revoked."}

@app.get("/api/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user_token)):
    return UserOut(id=current_user.id, email=current_user.email, is_verified=current_user.is_verified)
def me(current_user: User = Depends(get_current_user_token)):
