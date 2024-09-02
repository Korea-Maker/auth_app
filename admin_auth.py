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
    # 로그인 엔드포인트는 제외  
    if request.endpoint == 'admin_auth_bp.login':  
        return  # 로그인 엔드포인트에서는 검증을 수행하지 않음  
    
    token = request.cookies.get('token')  
    
    if not token:  
        return jsonify({"status": "실패", "message": "토큰이 없습니다"}), 401  
    
    decoded = verify_token(token)  
    if not decoded:  
        return jsonify({"status": "실패", "message": "유효하지 않거나 만료된 토큰입니다"}), 401  

    # 요청에 사용자 정보를 추가  
    request.user = decoded['username'] 
    
@admin_auth_bp.route('/login', methods=['POST'])
def login():
    db = connect_mongo()
    id = request.json.get('id')
    pw = request.json.get('pw')
    user = mongo_find_user(db, id, pw)
    
    if user is not None:
        token = generate_token(id)
        token_str = token.decode('utf-8')  # 바이트를 문자열로 디코딩 => 응답에 포함하기 위함인데 이전에 바이트로 응답을 보낼 경우 에러가 발생했었음
        response = make_response(jsonify({"status": "성공"}))
        response.set_cookie('token', token_str, httponly=True, secure=True, samesite='Lax')
        response.headers.add('Access-Control-Allow-Origin', 'https://resume.jongwook.xyz')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
    else:
        return jsonify({"status": "실패"}), 401

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