# main.py

# Importing Base Libraries
import os
from fastapi import FastAPI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialising FastAPI
app = FastAPI()

# Import routers
from user import router as user_router  # Import the router from user.py
from admin import router as admin_router  # Import the router from admin.py

# Include routers
app.include_router(user_router)
app.include_router(admin_router)
