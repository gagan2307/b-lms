# admin.py

from fastapi import APIRouter, Depends, HTTPException, status, Form
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
@router.post("/addUser")
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
# Delete User via Admin Only
# -----------------------------------------------------------------------
@router.delete("/deleteUser")
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



@router.get("/pendingLeaves")
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
