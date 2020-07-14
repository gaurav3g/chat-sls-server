import boto3
import logging
import time
import uuid

from utils.jwt_utils import jwt_encode

logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)


dynamo_db = boto3.resource("dynamodb")


def get_access_token(email=""):
    curr_time = int(time.time())
    token_obj = {
        "exp": curr_time + 3600,
        "iat": curr_time,
        "email": email
    }
    return jwt_encode(token_obj)


def get_refresh_token(email="", access_token=""):
    return jwt_encode({
        "uuid": str(uuid.uuid1()),
        "token": str(access_token),
        "email": email
    })


def get_auth_tokens(username=""):
    access_token = get_access_token(username)
    refresh_token = get_refresh_token(username, access_token)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
