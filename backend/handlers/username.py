import boto3
import json
import jwt
import logging
import time
import uuid
from lambda_decorators import cors_headers

from handlers.handler import _get_response, _get_body
from utils.username import get_username
from utils.auth_token_generator import get_auth_tokens

logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)

dynamodb = boto3.resource("dynamodb")

@cors_headers
def check_username(event, context, items=None):
    if event['queryStringParameters']['username'] is None:
        return _get_response(400, "'{}' not in request" \
                             .format("username"))

    username = event['queryStringParameters']['username'].lower()

    username_obj = get_username(username)

    if len(username_obj) > 0:
        return _get_response(200, {"status": 1, "message": "username already exist"})
    else:
        return _get_response(200, {"status": 0, "message": "username don't exist"})


@cors_headers
def set_username(event, context, items=None):
    body = _get_body(event)
    logger.info(body)
    if body['username'] is None:
        return _get_response(400, "'{}' not in request" \
                             .format("username"))

    username = body['username'].lower()
    username_table = dynamodb.Table("serverless-chat_Username")

    username_obj = get_username(username)

    if len(username_obj) > 0:
        return _get_response(404, "Username already exists")
    else:
        # username_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, username))
        tokens = get_auth_tokens(username)
        try:
            usernameObj = {"Username": username,
                           "accessToken": tokens["access_token"],
                           "refreshToken": tokens["refresh_token"]}
            username_table.put_item(Item=usernameObj)
            return _get_response(200, usernameObj)
        except:
            return _get_response(404, "Username can't create")
