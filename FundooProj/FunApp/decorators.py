from .services import RedisCreate
import jwt
import os
from FunApp import views
def login_user(arg):
    print("in decorator",arg)
    redis_object=RedisCreate()
    jwt_token=redis_object.get('token')
    decoded_token=jwt.decode(jwt_token,os.getenv('SECRET_KEY_JWT'))
    user_id=decoded_token['id']