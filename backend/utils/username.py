import boto3
import json
import logging

logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)


dynamo_db = boto3.resource("dynamodb")


def get_username(search_str=""):
    username_obj = []
    if type(search_str) == str and search_str != "":
        username_table = dynamo_db.Table("serverless-chat_Username")

        try:
            username_response = username_table.query(KeyConditionExpression="Username = :username",
                                                     ExpressionAttributeValues={":username": search_str},
                                                     Limit=1)
            username_obj = username_response.get("Items", [])
        except:
            logger.debug("Failed: Table parse failed.")

        return username_obj
