from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
from authlib.jose import jwt
from datetime import datetime, timedelta
import os

# Initialize Flask app
app = Flask(__name__)

# Allow CORS from specific origins and support credentials
CORS(app, resources={r"/*": {"origins": ["http://127.0.0.1:3000", "http://localhost:3000"]}}, supports_credentials=True)

# Load environment variables
load_dotenv()
MONGO_USERNAME = os.environ.get('MONGO_USERNAME_AUTH')
MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD_AUTH')
MONGO_HOST = os.environ.get('MONGO_HOST')
MONGO_PORT = os.environ.get('MONGO_PORT')
MONGO_DB = os.environ.get('MONGO_AUTH_DB')
MONGO_COLLECTION = os.environ.get('MONGO_AUTH_COLLECTION')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')

# MongoDB connection
def connect_mongo():
    client = MongoClient(f"mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}")
    db = client[MONGO_DB]
    collection = db[MONGO_COLLECTION]
    return collection

# Find user in MongoDB
def mongo_find_user(collection, username, password):
    user = collection.find_one({
        "username": username,
        "password": password
    })
    return user

# Update user password in MongoDB
def mongo_update_user(collection, username, password):
    collection.update_one({
        "username": username},
        {"$set": 
            {
                "password": password
                }
            }
        )
    return None

# Generate JWT token
def generate_token(username):
    header = {"alg": "HS256"}
    payload = {
        "username": username,
        "exp": datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }
    token = jwt.encode(header, payload, JWT_SECRET_KEY)
    return token

# Verify JWT token
def verify_token(token):
    try:
        decoded = jwt.decode(token, JWT_SECRET_KEY)
        # Check if the token is expired
        if datetime.utcnow() > datetime.utcfromtimestamp(decoded['exp']):
            print("Token expired")
            return None
        return decoded
    except Exception as e:
        print(f"Error decoding token: {e}")
        return None

# Login route
@app.route('/auth/login', methods=['POST'])
def login():
    db = connect_mongo()
    id = request.json.get('id')
    pw = request.json.get('pw')
    user = mongo_find_user(db, id, pw)
    
    if user is not None:
        token = generate_token(id)
        token_str = token.decode('utf-8')  # Decode bytes to string
        response = make_response(jsonify({"status": "success"}))
        response.set_cookie('token', token_str, httponly=True, secure=True, samesite='None')
        print(f"Set-Cookie Header: token={token_str}")  # Debugging output
        return response
    else:
        return jsonify({"status": "fail"}), 401

# Protected route example
@app.route('/auth/protected', methods=['GET'])
def protected():
    token = request.cookies.get('token')  # Read token from HTTP-only cookie
    print(f"Received token: {token}")  # Debugging
    if not token:
        return jsonify({"status": "fail", "message": "Token missing"}), 401
    
    decoded = verify_token(token)
    if not decoded:
        return jsonify({"status": "fail", "message": "Invalid or expired token"}), 401

    return jsonify({"status": "success", "message": "Access granted to protected route"})

# Update user route (Optional example for completeness)
@app.route('/auth/update', methods=['PUT'])
def update_auth():
    token = request.cookies.get('token')  # Read token from HTTP-only cookie
    if not token:
        return jsonify({"status": "fail", "message": "Token missing"}), 401
    
    decoded = verify_token(token)
    if not decoded:
        return jsonify({"status": "fail", "message": "Invalid or expired token"}), 401
    
    db = connect_mongo()
    id = decoded['username']
    new_pw = request.json.get('new_pw')
    
    mongo_update_user(db, id, new_pw)
    return jsonify({"status": "success"})

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5000)
