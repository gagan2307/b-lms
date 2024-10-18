# admin.py

from fastapi import APIRouter, Depends, HTTPException, status, Form, Path, Query
from fastapi.responses import JSONResponse
import os
import requests
import bcrypt
import json
import uuid

# Import helper functions
from helper import parse_firebase_error, get_current_user, send_registration_email, verify_token, verify_password

from firebase_admin import auth as admin_auth
from config.firebase_config import firestore_db

router = APIRouter()

# -----------------------------------------------------------------------
# App Routes
# Add-User endpoint
# -----------------------------------------------------------------------
@router.post("/admin/addUser")
def add_user(
    email: str = Form(...),
    password: str = Form(...),
    username: str = Form(...),
    firstname: str = Form(...),
    lastname: str = Form(...),
    emp_type: str = Form("regular"),
    dept: str = Form("IT"),
    role: str = Form("user"),
    current_user: dict = Depends(get_current_user)
):
    # Authorization check: only admins can delete users
    if current_user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Not authorized to perform this action")
    
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
            "password": hashed_password,
            "uid": uid,
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
# Admin-Login endpoint
# -----------------------------------------------------------------------
@router.post("/admin/signin")
def admin_signin(email: str = Form(...), password: str = Form(...)):
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
        response_firebase = requests.post(url, json=payload, headers=headers)
        response_firebase.raise_for_status()
        data = response_firebase.json()
        id_token = data['idToken']
        refresh_token = data['refreshToken']
        local_id = data['localId']

        # Use local_id as uid
        uid = local_id

        # Fetch user data from Firestore to check the role
        user_doc = firestore_db.collection('users').document(uid).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            role = user_data.get('role')
            if role != 'admin':
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. Not an admin user.")
        else:
            raise HTTPException(status_code=404, detail="User data not found / Or User not an Admin")

        # Create JSON response and set the cookie
        response = JSONResponse(content={
            "message": "Admin signed in successfully",
            "idToken": id_token,
            "refreshToken": refresh_token
        })

        response.set_cookie(
            key="__session",
            value=id_token,
            httponly=True,  # Prevents JavaScript access to the cookie
            # secure=True,    # Only send cookie over HTTPS
            # samesite='Lax', # Controls cross-origin cookie behavior
            max_age=3600    # Cookie expires in 1 hour
        )

        return response

    except requests.exceptions.HTTPError as e:
        error_message = e.response.json().get('error', {}).get('message', 'An error occurred')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)
    except Exception as e:
        error_message = str(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)


# -----------------------------------------------------------------------
# App Routes
# Delete User via Admin Only
# -----------------------------------------------------------------------
@router.delete("/admin/deleteUser")
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
# Admin: Fetch pending leave
# -----------------------------------------------------------------------
@router.get("/admin/pendingLeaves")
def get_pending_leaves(
    decoded_token=Depends(verify_token),
    current_user: dict = Depends(get_current_user)  # Ensure the user is logged in
):
    try:
        # Check if the user is an admin or has the necessary role to access pending leaves
        if current_user.get("role") not in ['admin']:
            raise HTTPException(status_code=403, detail="Access denied. Only admins can view pending leaves.")

        # Fetch all leaves with status 'pending' from the leaves collection
        leaves_ref = firestore_db.collection('leaves')
        pending_leaves_query = leaves_ref.where('status', '==', 'pending').stream()
        
        pending_leaves = []
        for leave_doc in pending_leaves_query:
            leave_data = leave_doc.to_dict()
            pending_leaves.append({
                "username": leave_data.get("username"),
                "applied_on": leave_data.get("applied_on"),
                "from_date": leave_data.get("from_date"),
                "to_date": leave_data.get("to_date"),
                "leave_type": leave_data.get("leave_type"),
                "leave_id": leave_data.get("leave_id")
            })

        total_number_pending_leaves = len(pending_leaves)

        if total_number_pending_leaves == 0:
            return {
                "message": "No pending leaves found.",
                "total_number_pending_leaves": 0
            }
        
        return {
            "total_number_pending_leaves": total_number_pending_leaves,
            "pending_leaves": pending_leaves
        }

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        error_message = str(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)
    

# -----------------------------------------------------------------------
# App Routes
# Admin: Update Leave Status
# -----------------------------------------------------------------------
@router.put("/admin/update-leave-status")
def update_leave_status(
    leave_id: str = Form(...),
    status: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Admin endpoint to update the status of a pending leave application.
    Only accessible by users with the 'admin' role.
    """
    # Authorization check: only admins can update leave status
    if current_user.get("role") not in ['admin']:
        raise HTTPException(status_code=403, detail="Access denied. Only admins can update leave status.")

    # Validate the status value
    if status not in ['approved', 'denied']:
        raise HTTPException(status_code=400, detail="Invalid status. Must be 'approved' or 'denied'.")

    try:
        # Find the leave document by leave_id
        leaves_ref = firestore_db.collection('leaves')
        leave_doc = leaves_ref.document(leave_id).get()
        if not leave_doc.exists:
            raise HTTPException(status_code=404, detail="Leave application not found.")

        # Update the 'status' field
        leaves_ref.document(leave_id).update({'status': status})

        return {"message": f"Leave application {leave_id} status updated to '{status}'."}

    except Exception as e:
        error_message = str(e)
        raise HTTPException(status_code=500, detail=error_message)
    
# -----------------------------------------------------------------------
# App Routes
# Admin: Get Leave Details
# -----------------------------------------------------------------------
@router.get("/admin/leave")
def get_leave_details(
    leave_id: str = Query(..., description="The unique identifier of the leave application"),
    current_user: dict = Depends(get_current_user)
):
    """
    Admin endpoint to get the details of a leave application by leave_id.
    Only accessible by users with the 'admin' role.
    """
    # Authorization check: only admins can access this endpoint
    if current_user.get("role") != 'admin':
        raise HTTPException(status_code=403, detail="Access denied. Only admins can access leave details.")

    try:
        # Retrieve the leave document from Firestore
        leaves_ref = firestore_db.collection('leaves')
        leave_doc = leaves_ref.document(leave_id).get()
        if not leave_doc.exists:
            raise HTTPException(status_code=404, detail="Leave application not found.")

        leave_data = leave_doc.to_dict()

        return {"leave_details": leave_data}

    except Exception as e:
        error_message = parse_firebase_error(e)
        raise HTTPException(status_code=500, detail=error_message)
    

@router.get("/admin/fetchLeaves")
def get_denied_leaves(
    decoded_token=Depends(verify_token),
    current_user: dict = Depends(get_current_user)  # Ensure the user is logged in
):
    try:
        # Check if the user is an admin or has the necessary role to access pending leaves
        if current_user.get("role") not in ['admin']:
            raise HTTPException(status_code=403, detail="Access denied. Only admins can view denied leaves.")

        # Fetch all leaves with status 'pending' from the leaves collection
        leaves_ref = firestore_db.collection('leaves')
        fetch_leaves_query = leaves_ref.where('status', 'in', ['denied', 'approved']).stream()
        
        approved_leaves = []
        denied_leaves = []
        for leave_doc in fetch_leaves_query:
            leave_data = leave_doc.to_dict()
            if leave_data.get('status') == 'approved' :
                approved_leaves.append({
                    "username": leave_data.get("username"),
                    "applied_on": leave_data.get("applied_on"),
                    "from_date": leave_data.get("from_date"),
                    "to_date": leave_data.get("to_date"),
                    "leave_type": leave_data.get("leave_type"),
                })
            
            if leave_data.get('status') == 'denied' :
                denied_leaves.append({
                    "username": leave_data.get("username"),
                    "applied_on": leave_data.get("applied_on"),
                    "from_date": leave_data.get("from_date"),
                    "to_date": leave_data.get("to_date"),
                    "leave_type": leave_data.get("leave_type"),
                })
            
            

        total_number_denied_leaves = len(denied_leaves)

        total_number_approved_leaves = len(approved_leaves)
                     
        return {
            "total_number_denied_leaves": total_number_denied_leaves,
            "denied_leaves": denied_leaves,
            "total_number_approved_leaves": total_number_approved_leaves,
            "approved_leaves": approved_leaves
            
        }

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        error_message = str(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_message)
    
    

