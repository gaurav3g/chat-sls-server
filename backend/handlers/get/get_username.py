import boto3
import json
import jwt
import logging
import time
import uuid
from lambda_decorators import cors_headers

from handlers.handler import _get_response, _get_body

logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)

dynamodb = boto3.resource("dynamodb")

@cors_headers
def get_username(event, context, items=None):
    if event['queryStringParameters']['username'] is None:
        logger.debug("Failed: '{}' not in request." \
                     .format("username"))
        return _get_response(400, "'{}' not in request" \
                             .format("username"))

    username = event['queryStringParameters']['username'].lower()
    username_table = dynamodb.Table("serverless-chat_Username")

    try:
        username_response = username_table.query(KeyConditionExpression="Username = :username",
                                                 ExpressionAttributeValues={":username": username},
                                                 Limit=1)
        username_obj = username_response.get("Items", [])
    except Error:
        logger.debug("Failed: Table parse failed.")
        return _get_response(400, "Table parse failed.")

    if len(username_obj) > 0:
        return _get_response(404, "username already exist")
    else:
        username_table.put_item(Item={"Username": username})
        return _get_response(200, "username created")

