import jwt
import os
import base64


def generate_jwt(payload, secret=""):
    return jwt.encode(payload, secret, algorithm="HS256")

def decode_jwt(token, secret=""):
    return jwt.decode(token, secret, algorithms=["HS256"])

def generate_token():
    try:
        # Создаем массив байтов для токена (32 байта = 256 бит)
        b = os.urandom(32)
        # Кодируем токен в base64
        return base64.b64encode(b).decode('utf-8')
    except Exception as e:
        print(f"Error generating token: {e}")
        return None