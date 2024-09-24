import firebase_admin
from firebase_admin import credentials

# Path to your service account key JSON file
cred = credentials.Certificate("../serviceAccountKey/serviceConfig.json")
firebase_admin.initialize_app(cred)
