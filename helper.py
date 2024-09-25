from fastapi import FastAPI, Depends, HTTPException, status, Form,Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from firebase_admin import auth as admin_auth, firestore
import os
import bcrypt
import smtplib  # Import smtplib for SMTP
from email.mime.text import MIMEText  # Import MIMEText
from email.mime.multipart import MIMEMultipart  # Import MIMEMultipart
from config.firebase_config import firestore_db  # Import the Firestore client

load_dotenv()

security = HTTPBearer()

def parse_firebase_error(e):
    try:
        error_message = str(e)
        return error_message
    except Exception:
        return "An unknown error occurred."
    
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        decoded_token = admin_auth.verify_id_token(token)
        uid = decoded_token['uid']
        # Fetch user data from Firestore
        user_doc = firestore_db.collection('users').document(uid).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            return user_data
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

def send_registration_email(to_email, uid, password, verification_link):
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    smtp_username = os.getenv('SMTP_USERNAME')
    smtp_password = os.getenv('SMTP_PASSWORD')
    smtp_server = os.getenv('SMTP_SERVER')

    try:
        # Create the email content
        subject = "Your Account Details and Verification Link"
        body = f"""
        Dear User,

        Your account has been created successfully. Below are your account details:

        Email:{to_email}
        UID: {uid}
        Password: {password}

        Please verify your email address by clicking on the link below:
        {verification_link}

        Best regards,
        Babagang and Co.
        """

        # Set up the MIME
        message = MIMEMultipart()
        message['From'] = smtp_username
        message['To'] = to_email
        message['Subject'] = subject

        # Attach the body with the msg instance
        message.attach(MIMEText(body, 'plain'))

        # Create SMTP session
        session = smtplib.SMTP(smtp_server, smtp_port)  # Use Gmail's SMTP server
        session.starttls()  # Enable security
        session.set_debuglevel(1)
        session.login(smtp_username, smtp_password)  # Login with your email and app password

        text = message.as_string()
        session.sendmail(smtp_username, to_email, text)
        session.quit()
        return f"Email Successfull Sent"
    except Exception as e:
        # Log the exception or handle accordingly
        print(f"Failed to send email: {e}")
        # Optionally, you might want to raise an exception or handle the error

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
    

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against its hashed version."""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))