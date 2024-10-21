# main.py

# Importing Base Libraries
import os
from fastapi import FastAPI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initializing FastAPI
app = FastAPI()

# Import the AuthMiddleware from middleware.py
from middleware import AuthMiddleware

# Add CORS middleware
from fastapi.middleware.cors import CORSMiddleware

# Configure CORS to accept requests from any origin (for development/testing)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],         # Accept all origins (adjust for production)
    allow_credentials=True,      # Important to allow cookies
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add the AuthMiddleware
app.add_middleware(AuthMiddleware)

# Import routers
from user import router as user_router  # Import the router from user.py
from admin import router as admin_router  # Import the router from admin.py

# Include routers
app.include_router(user_router)
app.include_router(admin_router)