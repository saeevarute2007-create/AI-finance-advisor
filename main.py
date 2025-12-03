from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta

# Secret key for JWT

SECRET_KEY = "mysecretkey123"  # Keep this secret in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# Password hashing

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dummy database

fake_users_db = {
"[user@example.com](mailto:user@example.com)": {
"name": "John Doe",
"email": "[user@example.com](mailto:user@example.com)",
"hashed_password": pwd_context.hash("password123")
}
}

# Pydantic models

class Token(BaseModel):
access_token: str
token_type: str

class User(BaseModel):
name: str
email: str

# Helper functions

def verify_password(plain_password, hashed_password):
return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(email: str, password: str):
user = fake_users_db.get(email)
if not user or not verify_password(password, user["hashed_password"]):
return False
return user

def create_access_token(data: dict, expires_delta: timedelta = None):
to_encode = data.copy()
expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
to_encode.update({"exp": expire})
return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
credentials_exception = HTTPException(
status_code=status.HTTP_401_UNAUTHORIZED,
detail="Could not validate credentials",
headers={"WWW-Authenticate": "Bearer"},
)
try:
payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
email: str = payload.get("sub")
if email is None:
raise credentials_exception
user = fake_users_db.get(email)
if user is None:
raise credentials_exception
return user
except JWTError:
raise credentials_exception

# Routes

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
user = authenticate_user(form_data.username, form_data.password)
if not user:
raise HTTPException(status_code=400, detail="Incorrect username or password")
access_token = create_access_token(data={"sub": user["email"]},
expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
return {"access_token": access_token, "token_type": "bearer"}

@app.get("/finance-advice")
async def get_finance_advice(current_user: User = Depends(get_current_user)):
# Example AI-powered finance advice (simple dummy logic)
advice = {
"user": current_user["name"],
"advice": "Invest 20% of your income in mutual funds, save 30% for emergency, and reduce unnecessary expenses."
}
return advice
