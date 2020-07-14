import boto3
import json
import jwt
import logging
import time
import uuid
from lambda_decorators import cors_headers

from handlers.handler import _get_response, _get_body
from utils.user import get_user_by_email
from utils.auth_token_generator import get_auth_tokens

logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)

dynamodb = boto3.resource("dynamodb")


@cors_headers
def get_user(event, context):
    if event['queryStringParameters']['email'] is None:
        return _get_response(400, "'{}' not in request" \
                             .format("email"))

    email = event['queryStringParameters']['email']

    user_obj = get_user_by_email(email)

    if len(user_obj) > 0:
        return _get_response(200, {"status": 1, "message": "user already exist"})
    else:
        return _get_response(200, {"status": 0, "message": "user don't exist"})


@cors_headers
def set_user(event, context):
    body = _get_body(event)
    if body['email'] is None:
        return _get_response(400, "'{}' not in request" \
                             .format("email"))

    email = body['email']
    user_table = dynamodb.Table("serverless-chat_Users")

    user_obj = get_user_by_email(email)

    if len(user_obj) > 0:
        return _get_response(404, "User already exists")
    else:
        # username_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, username))
        tokens = get_auth_tokens(email)
        try:
            user_item = {"Email": email,
                         "email_verified": False,
                         "Username": email.split("@")[0],
                         "accessToken": tokens["access_token"],
                         "refreshToken": tokens["refresh_token"],
                         "ConnectionID": ""
                         }
            user_table.put_item(Item=user_item)
            return _get_response(200, user_item)
        except:
            return _get_response(404, "User can't create")
