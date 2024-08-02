import firebase_admin
from firebase_admin import credentials, auth

cred = credentials.Certificate("myecdsasign-firebase-adminsdk-rstgn-b824cd1141.json")
firebase_admin.initialize_app(cred)
