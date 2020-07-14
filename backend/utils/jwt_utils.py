import jwt
import json
import logging
import time
from jwt import ExpiredSignatureError

logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)


def jwt_encode(obj):
    try:
        return jwt.encode(obj,
                          '#0wc-0-#@#14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=',
                          algorithm='HS256').decode('utf-8')
    except ValueError:
        logger.debug("Failed: Unable to generate JWT")
        return ""


def jwt_decode(token):
    try:
        return jwt.decode(token,
                          "#0wc-0-#@#14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=",
                          algorithms="HS256")
    except ExpiredSignatureError as e:
        return {"exp": int(time.time()-1)}
    except ValueError:
        logger.debug("Failed: Unable to decode JWT token")
        return ""


