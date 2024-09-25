# main.py

# Importing Base Libraries
import os
import requests
import bcrypt
import json  
import uuid

# Importing Additional Libraries
from pydantic import BaseModel
from typing import Dict
from fastapi import FastAPI, Depends, HTTPException, status, Form,APIRouter, Response
from fastapi.security import HTTPBearer
from firebase_admin import auth as admin_auth
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from config.firebase_config import firestore_db  # Import the Firestore client
from dotenv import load_dotenv

# Importing Helper Functions
from helper import parse_firebase_error, get_current_user, send_registration_email, verify_token, verify_password

# Load environment variables
load_dotenv()

# Initialising FastAPI
app = FastAPI()
security = HTTPBearer()

# Add session middleware (if not already added)
app.add_middleware(SessionMiddleware, secret_key="your_secret_key")

# -----------------------------------------------------------------------
# App Routes
# Base Route
# -----------------------------------------------------------------------
@app.get('/')
def root():
    return {'message': 'This is the Base URL'}

# -----------------------------------------------------------------------
# App Routes
# Add-User endpoint
# -----------------------------------------------------------------------
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

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Create the Firestore user document with the given structure
        user_data = {
            "email": email,
            "username": username,
            "firstname": firstname,
            "lastname": lastname,
            "dept": dept,
            "emp_type": emp_type,
            "leaves": [],
            "role": 'user',
            "password": hashed_password  
        }

        # Save user data to Firestore (users collection)
        firestore_db.collection('users').document(uid).set(user_data)

        # Optional: Send email verification link
        link = admin_auth.generate_email_verification_link(email)
        # You need to send this link to the user's email address
        # Implement email sending functionality (e.g., using SMTP, SendGrid)

        # Send email containing uid, password, and verification link
        response = send_registration_email(email, uid, password, link)

        return {"message": "User created successfully", "uid": uid, "verificationLink": link, "Email Status": response}
    except admin_auth.EmailAlreadyExistsError:
        raise HTTPException(status_code=400, detail="Email already exists")
    except HTTPException as http_exc:
        # Re-raise HTTP exceptions
        raise http_exc
    except Exception as e:
        error_message = parse_firebase_error(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)


# -----------------------------------------------------------------------
# App Routes
# Delete User via Admin Only
# -----------------------------------------------------------------------
@app.delete("/deleteUser")
def delete_user(
    email: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    # Authorization check: only admins can delete users
    if current_user.get('role') != 'admin':
        
        raise HTTPException(status_code=403, detail="Not authorized to perform this action")

    try:
        # Find user by email in Firebase Authentication
        user_record = admin_auth.get_user_by_email(email)
        uid = user_record.uid

        # Delete user from Firebase Authentication
        admin_auth.delete_user(uid)
        # Delete user document from Firestore
        firestore_db.collection('users').document(uid).delete()
        return {"message": f"User with email {email} deleted successfully"}
    except admin_auth.UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found in Firebase Authentication")
    except Exception as e:
        error_message = parse_firebase_error(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)
    

# -----------------------------------------------------------------------
# App Routes
# Sign-in endpoint
# -----------------------------------------------------------------------
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


# -----------------------------------------------------------------------
# App Routes
# Refresh token endpoint
# -----------------------------------------------------------------------
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
    
# -----------------------------------------------------------------------
# App Routes
# Apply Leave for User
# -----------------------------------------------------------------------
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
        user_leaves = []

        for user_doc in query:
            user_exists = True
            user_doc_id = user_doc.id
            user_leaves = user_doc.to_dict().get('leaves', [])  # Retrieve the user's current leaves list
        
        if not user_exists:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Ensure leave application doesn't overlap with existing leaves
        leave_ref = firestore_db.collection('leaves').where('username', '==', username).stream()
        for leave in leave_ref:
            existing_leave = leave.to_dict()
            if (from_date <= existing_leave['to_date'] and to_date >= existing_leave['from_date']):
                raise HTTPException(status_code=400, detail="Leave dates overlap with existing leave")

        # Generate a unique leave_id (you can use UUID or Firestore document ID)
        leave_id = str(uuid.uuid4())  # Alternatively, use firestore_db.collection('leaves').document().id for Firestore-generated ID

        # Save leave data to Firestore (leaves collection)
        leave_data = {
            "leave_id": leave_id,  # Add unique leave ID
            "username": username,
            "leave_type": leave_type,
            "half": half,  # Add half to leave_data, it will be None if not provided
            "from_date": from_date,
            "to_date": to_date,
            "no_of_days": no_of_days,
            "applied_on": applied_on,
            "reason_for_leave": reason_for_leave,
            "adjusted_to": adjusted_to_dict,  # Save as a dictionary in Firestore
            "status": "pending",
            "admin_remark": "TBD"
        }
        firestore_db.collection('leaves').document(leave_id).set(leave_data)

        # Append the leave_id to the user's leaves list and update the user document
        user_leaves.append(leave_id)
        users_ref.document(user_doc_id).update({"leaves": user_leaves})

        return {"message": "Leave applied successfully", "leave_id": leave_id}
    
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        error_message = str(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)

    
# -----------------------------------------------------------------------
# App Routes
# User Leave History
# -----------------------------------------------------------------------
@app.get("/myLeaveHistory")
def my_leave_history(
    decoded_token=Depends(verify_token),
    current_user: dict = Depends(get_current_user)  # Ensure the user is logged in
):
    try:
        print(current_user)
        # Get the username from the decoded token
        username = current_user.get("username")
        
        # Check if the user exists and has the role 'user'
        users_ref = firestore_db.collection('users')
        query = users_ref.where('username', '==', username).limit(1).stream()
        user_data = None
        user_doc_id = None
        
        for user_doc in query:
            
            user_data = user_doc.to_dict()
            
            user_doc_id = user_doc.id
            
        
        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")

        if user_data.get('role') != 'user':
            raise HTTPException(status_code=403, detail="Access denied. Only users can view their leave history.")

        # Get the user's first and last name
        first_name = user_data.get("firstname", "")
        last_name = user_data.get("lastname", "")
        full_name = f"{first_name} {last_name}"

        # Fetch all leave_ids associated with the user from the user's leaves field
        user_leaves = current_user.get("leaves", [])
        print(user_leaves)

        # Fetch leave details from the leaves collection using the leave_ids
        leave_history = []
        if user_leaves:
            leaves_ref = firestore_db.collection('leaves')
            for leave_id in user_leaves:
                leave_query = leaves_ref.where("leave_id", "==", leave_id).limit(1).stream()
                for leave in leave_query:
                    leave_data = leave.to_dict()
                    leave_history.append({
                        "applied_on": leave_data.get("applied_on"),
                        "from_date": leave_data.get("from_date"),
                        "to_date": leave_data.get("to_date"),
                        "leave_type": leave_data.get("leave_type"),
                        "status": leave_data.get("status"),
                        "reason_for_leave":leave_data.get("reason_for_leave"),
                        "admin_remark":leave_data.get("admin_remark")
                        
                    })

        # Return the user's full name and leave history
        return {
            "name": full_name,
            "leave_history": leave_history
        }

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        error_message = str(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)



# -----------------------------------------------------------------------
# App Routes
# Change password
# ----------------------------------------------------------------------- 

@app.put("/change-password")
def change_password(
    current_password: str = Form(...),  # Accept form data
    new_password: str = Form(...),      # Accept form data
    decoded_token=Depends(verify_token),  
    current_user: dict = Depends(get_current_user) # Use the get_current_user function
):
    # Retrieve the stored hashed password from the current_user data
    stored_hashed_password = current_user.get('password')

    # Verify the current password
    if not verify_password(current_password, stored_hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Hash the new password
    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    user_record = admin_auth.get_user_by_email(current_user['email'])
    uid = user_record.uid
    # Update the password in Firestore
    user_ref = firestore_db.collection('users').document(uid)
    user_ref.update({'password': hashed_new_password})

    return {"message": "Password updated successfully"}

# -----------------------------------------------------------------------
# App Routes
# Protected route example
# -----------------------------------------------------------------------
@app.get("/protected")
def protected_route(decoded_token=Depends(verify_token)):
    email = decoded_token.get('email')
    return {"message": f"Welcome {email}"}

# -----------------------------------------------------------------------
# App Routes
# Logout endpoint (handled on the client-side)
# -----------------------------------------------------------------------
@app.post("/logout")
def logout(response: Response, decoded_token=Depends(verify_token)):
    try:
        # Clear session or JWT token
        response.delete_cookie(key="idToken")
        response.delete_cookie(key="refreshToken")

        # If using session-based auth, you can also clear the session
        response.delete_cookie(key="session")

        # Optionally, you can also invalidate the refresh token using Firebase REST API
        # (requires revoking the refresh token via an admin action)

        # Redirect the user to the homepage after logout
        return RedirectResponse(url="/", status_code=302)

    except Exception as e:
        error_message = str(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)


# -----------------------------------------------------------------------
# App Routes
# Another protected route example
# -----------------------------------------------------------------------
@app.get("/another-protected-route")
def another_route(decoded_token=Depends(verify_token)):
    # Access user info from decoded_token if needed
    return {"message": "This is a protected route"}


