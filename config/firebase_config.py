# config/firebase_config.py

import os
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, firestore
import pyrebase

load_dotenv()  # Load environment variables from .env file

# Firebase project configuration
firebase_config = {
    "apiKey": os.getenv("API_KEY"),
    "authDomain": os.getenv("AUTH_DOMAIN"),
    "projectId": os.getenv("PROJECT_ID"),
    "storageBucket": os.getenv("STORAGE_BUCKET"),
    "databaseURL": os.getenv("DATABASE_URL"),
    "messagingSenderId": os.getenv("MESSAGING_SENDER_ID"),
    "appId": os.getenv("APP_ID"),
}

# Initialize Firebase Admin SDK
cred = credentials.Certificate(os.getenv("SERVICE_ACCOUNT_PATH"))
firebase_admin.initialize_app(cred)

# Initialize Firestore
firestore_db = firestore.client()

# Initialize Pyrebase
firebase = pyrebase.initialize_app(firebase_config)
pyrebase_auth = firebase.auth()
