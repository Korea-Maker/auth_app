from flask import Blueprint, request, jsonify, make_response
from functools import wraps
from authlib.jose import jwt
from datetime import datetime, timedelta, timezone
import os
from pymongo import MongoClient
from dotenv import load_dotenv
from bson import ObjectId

load_dotenv()

admin_auth_bp = Blueprint('admin_auth_bp', __name__)

MONGO_USERNAME = os.environ.get('MONGO_USERNAME_AUTH')
MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD_AUTH')
MONGO_HOST = os.environ.get('MONGO_HOST')
MONGO_PORT = os.environ.get('MONGO_PORT')
MONGO_DB = os.environ.get('MONGO_AUTH_DB')
MONGO_COLLECTION = os.environ.get('MONGO_AUTH_COLLECTION')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
REFRESH_SECRET_KEY = os.environ.get('REFRESH_SECRET_KEY')

def connect_mongo():
    client = MongoClient(f"mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}")
    db = client[MONGO_DB]
    collection = db[MONGO_COLLECTION]
    return collection

def mongo_find_user(collection, username, password):
    user = collection.find_one({
        "username": username,
        "password": password
    })
    return user

def mongo_update_user(collection, username, password):
    collection.update_one(
        {
            "username": username
        },
        {
            "$set": {
                "password": password
            }
        }
    )
    return None

def generate_token(username):
    header = {"alg": "HS256"}
    payload = {
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)  # 토큰 만료 시간 설정
    }
    token = jwt.encode(header, payload, JWT_SECRET_KEY)
    return token

def generate_refresh_token(username):
    header = {"alg": "HS256"}
    payload = {
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(days=7)  # Refresh token expiration time
    }
    token = jwt.encode(header, payload, REFRESH_SECRET_KEY)
    return token

def verify_token(token):
    try:
        decoded = jwt.decode(token, JWT_SECRET_KEY)
        if datetime.now(timezone.utc) > datetime.fromtimestamp(decoded['exp'], timezone.utc):
            print("토큰이 만료되었습니다")
            return None
        return decoded
    except Exception as e:
        print(f"토큰 디코딩 오류: {e}")
        return None
    
@admin_auth_bp.before_request  
def check_jwt():  
    if request.endpoint == 'admin_auth_bp.login' or request.endpoint == 'admin_auth_bp.refresh':  
        return  # No verification for login and refresh endpoints

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
    
@admin_auth_bp.route('/login', methods=['POST'])
def login():
    db = connect_mongo()
    id = request.json.get('id')
    pw = request.json.get('pw')
    user = mongo_find_user(db, id, pw)
    
    if user is not None:
        access_token = generate_access_token(id)
        refresh_token = generate_refresh_token(id)
        access_token_str = access_token.decode('utf-8')
        refresh_token_str = refresh_token.decode('utf-8')
        
        response = make_response(jsonify({"status": "성공", "access_token": access_token_str}))
        response.set_cookie('refresh_token', refresh_token_str, httponly=True, secure=True, samesite='None')
        response.headers.add('Access-Control-Allow-Origin', 'https://resume.jongwook.xyz')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
    else:
        return jsonify({"status": "실패"}), 401
    
@admin_auth_bp.route('/refresh', methods=['POST'])
def refresh():
    refresh_token = request.cookies.get('refresh_token')
    if not refresh_token:
        return jsonify({"status": "실패", "message": "Refresh token이 없습니다"}), 401
    
    decoded = verify_token(refresh_token, REFRESH_SECRET_KEY)
    if not decoded:
        return jsonify({"status": "실패", "message": "유효하지 않거나 만료된 refresh token입니다"}), 401
    
    username = decoded['username']
    new_access_token = generate_access_token(username)
    access_token_str = new_access_token.decode('utf-8')
    
    return jsonify({"status": "성공", "access_token": access_token_str})

@admin_auth_bp.route('/protected', methods=['GET'])  
def protected():  
    return jsonify({"status": "성공", "message": "보호된 경로에 대한 액세스가 허용되었습니다"})  


# @admin_auth_bp.route('/update', methods=['PUT'])  
# def update_auth():  
#     db = connect_mongo()  
#     id = request.user  # 요청에 추가된 사용자 정보 사용  
#     new_pw = request.json.get('new_pw')  
    
#     mongo_update_user(db, id, new_pw)  
#     return jsonify({"status": "성공"}) 

# @admin_auth_bp.route('/users/update', methods=['POST'])  
# def update_user():  
#     db = connect_mongo()  
#     name = request.json.get('name')  
#     birth = request.json.get('birth')  
#     location = request.json.get('location')  
#     phone = request.json.get('phone')  
#     email = request.json.get('email')  
#     education = request.json.get('education')  

#     # 사용자 정보를 업데이트하는 로직을 추가하세요.  
    
#     return jsonify({"status": "성공", "message": "사용자 정보가 업데이트되었습니다."}) 