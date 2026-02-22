import os
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
import pymongo
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from bson import ObjectId
from pydantic import BaseModel, Field, BeforeValidator
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing_extensions import Annotated
from dotenv import load_dotenv

# --- Load Environment Variables ---
load_dotenv()  # This loads the variables from your .env file

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("No MONGO_URI found! Make sure you have a .env file or set the environment variable.")

DB_NAME = "anyrank"
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_secret_key") 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="Universal Ranking API")

# Required for connecting with ReactJS
origins = [
    "http://localhost:5173",     # Your Vite React App
    "http://127.0.0.1:5173",     # Alternative local IP for Vite
    "http://localhost:3000",     # Kept just in case you use Create React App later
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"]
)

# --- Database Setup (Updated for Atlas) ---
# motor handles the asynchronous connection pool automatically
client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

db = client.get_database("appdata")
users_collection = db.get_collection("users")
rankings_collection = db.get_collection("rankings")

# --- Security & Auth Utils ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- Pydantic Models ---
# Helper for ObjectId handling
PyObjectId = Annotated[str, BeforeValidator(str)]

class UserCreate(BaseModel):
    username: str
    password: str

# class RankingItem(BaseModel):
#     name: str
#     rank: int
#     metadata: Optional[dict] = None 

class RankingCreate(BaseModel):
    title: str 
    items: List[str]

class RankingResponse(RankingCreate):
    id: PyObjectId = Field(alias="_id") # Map MongoDB _id to id automatically
    user_username: str

# --- Dependencies ---
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = users_collection.find_one({"username": username})
    if user is None:
        raise credentials_exception
    return user

# --- Routes: Authentication ---

@app.post("/signup", status_code=201)
async def signup(user: UserCreate):
    existing_user = users_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    user_dict = user.model_dump()
    raw_pwd = user_dict.pop("password")
    print(f"raw_pwd: {raw_pwd}")
    user_dict["hashed_password"] = get_password_hash(raw_pwd)
    
    users_collection.insert_one(user_dict)

    access_token = create_access_token(data={"sub": user_dict["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# --- Routes: Rankings ---
# CREATE
@app.post("/rankings/", response_model=RankingResponse)
async def create_ranking(ranking: RankingCreate, current_user: dict = Depends(get_current_user)):
    ranking_data = ranking.model_dump()
    ranking_data["user_username"] = current_user["username"]
    ranking_data["created_at"] = datetime.now()
    
    new_ranking = rankings_collection.insert_one(ranking_data)
    created_ranking = rankings_collection.find_one({"_id": new_ranking.inserted_id})
    
    return created_ranking

# UPDATE
@app.put("/rankings/{ranking_id}", response_model=RankingResponse)
async def update_ranking(
    ranking_id: str, 
    ranking_update: RankingCreate, 
    current_user: dict = Depends(get_current_user)
):
    # 1. Validate the ID format so MongoDB doesn't crash
    if not ObjectId.is_valid(ranking_id):
        raise HTTPException(status_code=400, detail="Invalid ranking ID format")
    
    # 2. Verify the ranking exists AND belongs to this specific user
    existing_ranking = rankings_collection.find_one({
        "_id": ObjectId(ranking_id),
        "user_username": current_user["username"]
    })
    
    if not existing_ranking:
        raise HTTPException(
            status_code=404, 
            detail="Ranking not found or you do not have permission to edit it"
        )

    # 3. Prepare the new data
    update_data = ranking_update.model_dump()
    
    # 4. Update the document in MongoDB
    rankings_collection.update_one(
        {"_id": ObjectId(ranking_id)},
        {"$set": update_data}
    )
    
    # 5. Fetch and return the fresh, updated document
    updated_ranking = rankings_collection.find_one({"_id": ObjectId(ranking_id)})
    return updated_ranking

# READ
@app.get("/rankings/", response_model=List[RankingResponse])
async def get_my_rankings(limit: int = 3, current_user: dict = Depends(get_current_user)):
    # Retrieve only the logged-in user's rankings
    cursor = rankings_collection.find({"user_username": current_user["username"]}, limit=limit)
    cursor = cursor.sort("created_at", pymongo.DESCENDING)
    rankings = list(cursor)
    return rankings

# DELETE
@app.delete("/rankings/{ranking_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ranking(
    ranking_id: str, 
    current_user: dict = Depends(get_current_user)
):
    # 1. Validate the ID format
    if not ObjectId.is_valid(ranking_id):
        raise HTTPException(status_code=400, detail="Invalid ranking ID format")

    # 2. Attempt to delete the specific document for this user
    result = rankings_collection.delete_one({
        "_id": ObjectId(ranking_id),
        "user_username": current_user["username"]
    })

    # 3. Check if a document was actually deleted
    if result.deleted_count == 0:
         raise HTTPException(
            status_code=404, 
            detail="Ranking not found or you do not have permission to delete it"
        )
         
    # A 204 status code automatically returns an empty success response
    return

# @app.get("/rankings/all", response_model=List[RankingResponse])
# async def get_all_rankings():
#     # Public endpoint to see everyone's rankings
#     cursor = rankings_collection.find({})
#     rankings = await cursor.to_list(length=100)
#     return rankings