import boto3
import json
import logging

logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)


dynamo_db = boto3.resource("dynamodb")


def get_user_by_email(email=""):
    username_obj = []
    if type(email) == str and email != "":
        username_table = dynamo_db.Table("serverless-chat_Users")

        try:
            username_response = username_table.query(KeyConditionExpression="Email = :email",
                                                     ExpressionAttributeValues={":email": email},
                                                     Limit=1)
            username_obj = username_response.get("Items", [])
        except:
            logger.debug("Failed: Table parse failed.")

        return username_obj
