import boto3
import json
import logging
from helpers.db import db


logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)


def get_user_by_email(email=""):
    username_obj = []
    if type(email) == str and email != "":
        try:
            username_response = db.collection(u'users').document(email).get()
            if username_response.exists:
                username_obj.append({**username_response.to_dict(), 'email': email})
        except ValueError as e:
            logger.debug("Failed: Table parse failed.")

        return username_obj
