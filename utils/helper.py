import os
from datetime import datetime, timedelta

import jwt
from django.core.handlers.wsgi import WSGIRequest
from django.shortcuts import get_object_or_404


from utils.models import CustomException
from message_auth.models import User


jwt_sk = os.getenv("JWT_SECRET_KEY")
if not jwt_sk:
    raise Exception('JWT Secret key error.')

secret_questions = [
    'What is the name of your oldest cousin?',
    'What is the name of the city which you were born?',
    'What is your favorite social media app?'
]

# access token black list
black_list = []


def generate_access_token(user):
    payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(days=int(os.getenv('ACCESS_EXP_DURATION'))),
        'iat': datetime.utcnow()
    }

    return jwt.encode(payload, jwt_sk, algorithm='HS256')


def generate_refresh_token(user):
    payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(weeks=int(os.getenv('REFRESH_EXP_DURATION'))),
        'iat': datetime.utcnow()
    }

    return jwt.encode(payload, jwt_sk, algorithm='HS256')


def decode_token(token):
    payload = jwt.decode(token, jwt_sk, algorithms=['HS256'])
    return payload


def verify_token(request: WSGIRequest):
    """
    Verifies token attached to request and returns the User object if token is valid.
    Throws exception of type `CustomException` where token is invalid or expired.
    :param request: Request object
    :return: User
    """

    auth_header: str = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        raise CustomException('Authentication required', status=400)

    # if auth_header and auth_header.startswith('Bearer '):
    token = auth_header.split(' ')[1]
    if token in black_list:
        raise CustomException('Token is blacklisted.', status=400)
    try:
        payload = decode_token(token)
    except (jwt.InvalidTokenError, jwt.ExpiredSignatureError) as err:
        if err.__class__ is jwt.ExpiredSignatureError:
            raise CustomException('Expired token.', status=401)
        raise CustomException('Invalid token.', status=400)

    user = get_object_or_404(User, id=payload['user_id'])
    return user
