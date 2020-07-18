import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

cred = credentials.Certificate('/home/mindfire/chat-sls-server/serverless-chat-3g-firebase-adminsdk-d7mfd-ea213d3a33.json')
firebase_admin.initialize_app(cred)

db = firestore.client()
