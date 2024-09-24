# main.py

import requests
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from firebase_admin import auth as admin_auth, firestore
from config.firebase_config import pyrebase_auth, firestore_db  # Import the Pyrebase auth object
# Firebase Admin SDK is initialized upon importing firebase_config

app = FastAPI()
security = HTTPBearer()

# Helper function to parse Pyrebase errors
def parse_firebase_error(e):
    try:
        error_message = str(e)
        return error_message
    except Exception:
        return "An unknown error occurred."

    
# Function to hash passwords using bcrypt
def hash_password(password: str) -> str:
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_pw.decode('utf-8')

@app.get('/')
def root(): 
    return {'message': 'This is the Base URL'}

# Sign-up endpoint
@app.post("/signup")
def signup(
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
            "role": role
        }

        # Save user data to Firestore (users collection)
        firestore_db.collection('users').document(uid).set(user_data)

        # Optional: Send email verification link
        link = admin_auth.generate_email_verification_link(email)
        # You need to send this link to the user's email address
        # Implement email sending functionality (e.g., using SMTP, SendGrid)

        return {"message": "User created successfully", "uid": uid}
    except admin_auth.EmailAlreadyExistsError:
        raise HTTPException(status_code=400, detail="Email already exists")
    except Exception as e:
        error_message = parse_firebase_error(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)



# Sign-in endpoint
@app.post("/signin")
def signin(email: str = Form(...), password: str = Form(...)):
    try:
        user = pyrebase_auth.sign_in_with_email_and_password(email, password)
        id_token = user['idToken']
        refresh_token = user['refreshToken']
        return {
            "message": "User signed in successfully",
            "idToken": id_token,
            "refreshToken": refresh_token,
        }
    except Exception as e:
        error_message = parse_pyrebase_error(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)

# Token verification dependency
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    id_token = credentials.credentials
    try:
        decoded_token = admin_auth.verify_id_token(id_token)
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




@app.post("/refresh-token")
def refresh_token(refresh_token: str = Form(...)):
    try:
        api_key = firebase_config["apiKey"]
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
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="An error occurred")
    
@app.get("/another-protected-route")
def another_route(decoded_token=Depends(verify_token)):
    # Access user info from decoded_token if needed
    return {"message": "This is a protected route"}



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
