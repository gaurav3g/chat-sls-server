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
from utils.jwt_utils import jwt_decode

logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)

dynamo_db = boto3.resource("dynamodb")

@cors_headers
def get_tokens(event, context, items=None):
    body = _get_body(event)
    if not isinstance(body, dict):
        return _get_response(400, "Message body not in dict format.")
    for attribute in ["token"]:
        if attribute not in body:
            return _get_response(400, "'{}' not in message dict".format(attribute))


    try:
        username = event.get("requestContext", {}).get("authorizer", {}).get("username")
    except:
        return _get_response(400, "Can't access username.")

    username_obj = get_username(username)

    if len(username_obj) == 0:
        return _get_response(400, "Username not found.")

    if username_obj[0]["refreshToken"] != body.get("token"):
        return _get_response(400, "Invalid refresh token.")

    decoded_a_token = jwt_decode(username_obj[0]["accessToken"])

    if decoded_a_token["exp"] <= int(time.time()):
        tokens = get_auth_tokens(username)
        username_table = dynamo_db.Table("serverless-chat_Username")
        try:
            username_table.update_item(
                Key={'Username': username},
                UpdateExpression="set accessToken=:a, refreshToken=:r",
                ExpressionAttributeValues={
                    ':a': tokens['access_token'],
                    ':r': tokens['refresh_token']
                },
                ReturnValues="UPDATED_NEW"
            )
        except:
            return _get_response(400, "Unable to update table.")
    else:
        tokens = {
            "access_token": username_obj[0]["accessToken"],
            "refresh_token": username_obj[0]["refreshToken"]
        }
    
    return _get_response(200, {
        "accessToken": tokens["access_token"],
        "refreshToken": tokens["refresh_token"],
    })