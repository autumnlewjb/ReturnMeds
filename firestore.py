import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

# Use a service account
cred = credentials.Certificate('returnmeds-bd71b-firebase-adminsdk-3kdmo-d05c72ea7e.json')
firebase_admin.initialize_app(cred)

fdb = firestore.client()


def write_data(doc_name, data):
    fdb.collection('schedule').document(doc_name).set(data)

def read_ongoing_data(username):
    return fdb.collection('schedule').where('username', '==', username).stream()