import firebase_admin
from firebase_admin import credentials, auth

cred = credentials.Certificate("/webdigsin-firebase-adminsdk-odsxc-970c5380bc.json")
firebase_admin.initialize_app(cred)
