# main.py
from pydantic import BaseModel
from typing import Dict
import requests
import json  
from fastapi import FastAPI, Depends, HTTPException, status, Form,Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from firebase_admin import auth as admin_auth, firestore
from config.firebase_config import firestore_db  # Import the Firestore client
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = FastAPI()
security = HTTPBearer()

# Helper function to parse Firebase errors
def parse_firebase_error(e):
    try:
        error_message = str(e)
        return error_message
    except Exception:
        return "An unknown error occurred."

@app.get('/')
def root():
    return {'message': 'This is the Base URL'}

# Sign-up endpoint
@app.post("/addUser")
def add_user(
    email: str = Form(...),
    password: str = Form(...),
    username: str = Form(...),
    firstname: str = Form(...),
    lastname: str = Form(...),
    emp_type: str = Form("regular"),
    dept: str = Form("IT"),
    role: str = Form("user")
):
    try:
        # Check if the username already exists
        users_ref = firestore_db.collection('users')
        query = users_ref.where('username', '==', username).limit(1).stream()
        if any(query):
            # Username is taken
            raise HTTPException(status_code=400, detail="Username is already taken")

        # Create user in Firebase Auth using Firebase Admin SDK
        user_record = admin_auth.create_user(
            email=email,
            password=password
        )
        uid = user_record.uid

        # Create the Firestore user document with the given structure
        user_data = {
            "email": email,
            "username": username,
            "firstname": firstname,
            "lastname": lastname,
            "dept": dept,
            "emp_type": emp_type,
            "leaves": [],
            "role": 'user'
        }

        # Save user data to Firestore (users collection)
        firestore_db.collection('users').document(uid).set(user_data)

        # Optional: Send email verification link
        link = admin_auth.generate_email_verification_link(email)
        # You need to send this link to the user's email address
        # Implement email sending functionality (e.g., using SMTP, SendGrid)

        return {"message": "User created successfully", "uid": uid, "verificationLink": link}
    except admin_auth.EmailAlreadyExistsError:
        raise HTTPException(status_code=400, detail="Email already exists")
    except HTTPException as http_exc:
        # Re-raise HTTP exceptions
        raise http_exc
    except Exception as e:
        error_message = parse_firebase_error(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)

# Sign-in endpoint
@app.post("/signin")
def signin(email: str = Form(...), password: str = Form(...)):
    try:
        # Use Firebase Authentication REST API to sign in
        api_key = os.getenv('API_KEY')
        if not api_key:
            raise Exception("API key not found. Please set the API_KEY environment variable.")

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        headers = {
            "Content-Type": "application/json"
        }
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        id_token = data['idToken']
        refresh_token = data['refreshToken']
        local_id = data['localId']

        # Optional: Fetch additional user data from Firestore if needed
        user_doc = firestore_db.collection('users').document(local_id).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
        else:
            user_data = {}

        return {
            "message": "User signed in successfully",
            "idToken": id_token,
            "refreshToken": refresh_token,
            "userData": user_data
        }
    except requests.exceptions.HTTPError as e:
        error_message = e.response.json().get('error', {}).get('message', 'An error occurred')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)
    except Exception as e:
        error_message = str(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)

# Token verification dependency
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    id_token = credentials.credentials
    try:
        decoded_token = admin_auth.verify_id_token(id_token)
        if not decoded_token.get('email_verified'):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email not verified",
            )
        return decoded_token
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Protected route example
@app.get("/protected")
def protected_route(decoded_token=Depends(verify_token)):
    email = decoded_token.get('email')
    return {"message": f"Welcome {email}"}

# Logout endpoint (handled on the client-side)
@app.post("/logout")
def logout():
    # Firebase tokens are stateless; logout is managed client-side
    return {"message": "User logged out successfully"}

# Refresh token endpoint
@app.post("/refresh-token")
def refresh_token(refresh_token: str = Form(...)):
    try:
        api_key = os.getenv('API_KEY')
        if not api_key:
            raise Exception("API key not found. Please set the API_KEY environment variable.")

        refresh_url = f"https://securetoken.googleapis.com/v1/token?key={api_key}"
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }
        response = requests.post(refresh_url, data=payload)
        response.raise_for_status()
        data = response.json()
        new_id_token = data['id_token']
        new_refresh_token = data['refresh_token']
        return {
            "idToken": new_id_token,
            "refreshToken": new_refresh_token,
        }
    except requests.exceptions.HTTPError as e:
        error_message = e.response.json().get('error', {}).get('message', 'An error occurred')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)
    except Exception as e:
        error_message = str(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)

# Another protected route example
@app.get("/another-protected-route")
def another_route(decoded_token=Depends(verify_token)):
    # Access user info from decoded_token if needed
    return {"message": "This is a protected route"}




@app.post("/applyLeave")
def apply_leave(
    leave_type: str = Form(...),
    half: str = Form(None),  # Default value set to None
    from_date: str = Form(...),
    to_date: str = Form(...),
    no_of_days: str = Form(...),
    applied_on: str = Form(...),
    reason_for_leave: str = Form(...),
    adjusted_to: str = Form(...),  # Receiving adjusted_to as a string
    username: str = Form(...),
    decoded_token=Depends(verify_token)
):
    try:
        # Convert the adjusted_to string to a dictionary
        try:
            adjusted_to_dict = json.loads(adjusted_to)  # Convert string to dictionary
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid format for adjusted_to. Please send a valid JSON string.")
        
        # Check if the user exists in Firestore
        users_ref = firestore_db.collection('users')
        query = users_ref.where('username', '==', username).limit(1).stream()
        user_exists = False
        user_doc_id = None
        
        for user_doc in query:
            user_exists = True
            user_doc_id = user_doc.id
        
        if not user_exists:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Ensure leave application doesn't overlap with existing leaves
        leave_ref = firestore_db.collection('leaves').where('username', '==', username).stream()
        for leave in leave_ref:
            existing_leave = leave.to_dict()
            if (from_date <= existing_leave['to_date'] and to_date >= existing_leave['from_date']):
                raise HTTPException(status_code=400, detail="Leave dates overlap with existing leave")

        # Save leave data to Firestore (leaves collection)
        leave_data = {
            "username": username,
            "leave_type": leave_type,
            "half": half,  # Add half to leave_data, it will be None if not provided
            "from_date": from_date,
            "to_date": to_date,
            "no_of_days": no_of_days,
            "applied_on": applied_on,
            "reason_for_leave": reason_for_leave,
            "adjusted_to": adjusted_to_dict,  # Save as a dictionary in Firestore
            "status": "pending"
        }
        firestore_db.collection('leaves').add(leave_data)

        return {"message": "Leave applied successfully"}
    
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        error_message = str(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)


