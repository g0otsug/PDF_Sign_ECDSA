import firebase_admin
from firebase_admin import credentials, auth, db

cred = credentials.Certificate("ecdsaacs-firebase-adminsdk-lpmmp-6544eeae6b.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://ecdsaweb-default-rtdb.firebaseio.com/'
})
