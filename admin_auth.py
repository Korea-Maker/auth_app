# admin_auth.py

from flask import Blueprint, request, jsonify, make_response
from flask_cors import CORS
from functools import wraps
from authlib.jose import jwt
from datetime import datetime, timedelta, timezone
import os
from pymongo import MongoClient
from dotenv import load_dotenv
from bson import ObjectId

load_dotenv()

# Blueprint Setup
admin_auth_bp = Blueprint('admin_auth_bp', __name__)
CORS(admin_auth_bp, resources={r"/*": {"origins": "https://resume.jongwook.xyz"}}, supports_credentials=True)

# Environment Configuration
MONGO_USERNAME = os.environ.get('MONGO_USERNAME_AUTH')
MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD_AUTH')
MONGO_HOST = os.environ.get('MONGO_HOST')
MONGO_PORT = os.environ.get('MONGO_PORT')
MONGO_DB = os.environ.get('MONGO_AUTH_DB')
MONGO_COLLECTION = os.environ.get('MONGO_AUTH_COLLECTION')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
REFRESH_SECRET_KEY = os.environ.get('REFRESH_SECRET_KEY')

# MongoDB Connection
def connect_mongo():
    client = MongoClient(f"mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}")
    db = client[MONGO_DB]
    collection = db[MONGO_COLLECTION]
    return collection

# MongoDB Operations
def mongo_find_user(collection, username, password):
    return collection.find_one({"username": username, "password": password})

def mongo_update_user(collection, username, password):
    collection.update_one(
        {"username": username},
        {"$set": {"password": password}}
    )

# Token Generation and Verification
def generate_access_token(username):
    header = {"alg": "HS256"}
    payload = {
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)  # Token expiration set to 1 hour
    }
    token = jwt.encode(header, payload, JWT_SECRET_KEY)
    return token

def generate_refresh_token(username):
    header = {"alg": "HS256"}
    payload = {
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(days=1)  # Refresh token expiration set to 1 day
    }
    token = jwt.encode(header, payload, REFRESH_SECRET_KEY)
    return token

def verify_token(token, secret_key):
    try:
        decoded = jwt.decode(token, secret_key)
        if datetime.now(timezone.utc) > datetime.fromtimestamp(decoded['exp'], timezone.utc):
            print("Token has expired")
            return None
        return decoded
    except Exception as e:
        print(f"Token decoding error: {e}")
        return None

# Middleware for Authentication
@admin_auth_bp.before_request  
def check_jwt():  
    if request.method == 'OPTIONS':
        return  # Skip JWT validation for preflight requests

    exempt_routes = ['admin_auth_bp.login', 'admin_auth_bp.refresh']
    if request.endpoint in exempt_routes:
        return  # Skip JWT validation for specific endpoints

    token = None
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    else:
        token = request.cookies.get('token')

    if not token:
        return jsonify({"status": "실패", "message": "토큰이 없습니다"}), 401  

    decoded = verify_token(token, JWT_SECRET_KEY)  
    if not decoded:
        return jsonify({"status": "실패", "message": "유효하지 않거나 만료된 토큰입니다"}), 401  

    request.user = decoded['username']
    
@admin_auth_bp.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = 'https://resume.jongwook.xyz'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    return response

@admin_auth_bp.route('/login', methods=['POST'])
def login():
    db = connect_mongo()
    id = request.json.get('id')
    pw = request.json.get('pw')
    user = mongo_find_user(db, id, pw)
    
    if user:
        access_token = generate_access_token(id)
        refresh_token = generate_refresh_token(id)
        
        response = make_response(jsonify({"status": "성공", "access_token": access_token.decode('utf-8')}))
        
        # Set refresh token cookie with appropriate attributes
        response.set_cookie(
            'refresh_token', 
            refresh_token.decode('utf-8'), 
            httponly=True, 
            secure=True, 
            samesite='None', 
            path='/'  # Ensure the cookie is sent for all paths in the domain
        )
        response.headers.add('Access-Control-Allow-Origin', 'https://resume.jongwook.xyz')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
    else:
        return jsonify({"status": "실패"}), 401

    
@admin_auth_bp.route('/refresh', methods=['POST', 'OPTIONS'])
def refresh():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', 'https://resume.jongwook.xyz')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response, 200
    
    refresh_token = request.cookies.get('refresh_token')
    if not refresh_token:
        return jsonify({"status": "실패", "message": "Refresh token이 없습니다"}), 401
    
    decoded = verify_token(refresh_token, REFRESH_SECRET_KEY)
    if not decoded:
        return jsonify({"status": "실패", "message": "유효하지 않거나 만료된 refresh token입니다"}), 401
    
    username = decoded['username']
    new_access_token = generate_access_token(username)
    
    return jsonify({"status": "성공", "access_token": new_access_token.decode('utf-8')})

@admin_auth_bp.route('/authenticate', methods=['GET', 'OPTIONS'])
def authenticate():
    return jsonify({"status": "성공"}), 200

@admin_auth_bp.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({"status": "성공", "message": "로그아웃 되었습니다"}))
    response.set_cookie('refresh_token', '', expires=0, secure=True, httponly=True, samesite='None')
    response.headers.add('Access-Control-Allow-Origin', 'https://resume.jongwook.xyz')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response