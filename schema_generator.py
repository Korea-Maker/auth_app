from pymongo import MongoClient
from dotenv import load_dotenv
import os

def mongo_connect():
    load_dotenv()
    username = os.environ.get('MONGO_USERNAME')
    password = os.environ.get('MONGO_PASSWORD')
    client = MongoClient(f'mongodb://{username}:{password}@localhost:27017/')
    db = client['auth']
    return db

def mongo_schema_gen(username, pw):
    db = mongo_connect()
    if db is None:
        print("몽고DB에 연결하는 동안 오류가 발생했습니다.")
        return None
    try:
        user_schema = {
            "username": username,
            "password": pw
        }
        user_collection = db['users']
        user_collection.insert_one(user_schema)
        print("사용자가 정상적으로 생성되었습니다.")
        return user_collection
    except Exception as e:
        print(f"사용자 생성 중 오류가 발생했습니다. {e}")
        return None

if __name__ == '__main__':
    username = os.environ.get('AUTH_USERNAME')
    password = os.environ.get('AUTH_PASSWORD')
    
    mongo_schema_gen(username, password)