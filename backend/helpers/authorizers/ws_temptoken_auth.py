import logging
from jose import jwk, jwt

from utils.generate_auth_policy import generatePolicy

logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)


def lambda_handler(event, context):
    logger.info(event)
    try:
        payload = jwt.decode(event.get("queryStringParameters", {}).get('token'),
                             "#0wc-0-#@#14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=",
                             algorithms="HS256")
        username = payload.get("username")
        logger.info("Verified JWT for '{}'".format(username))
    except ValueError as err:
        logger.debug("Failed: Token verification failed.")
        return generatePolicy(None, 'Deny', event['methodArn'])

    logger.info(generatePolicy("user", 'Allow', event['methodArn'], {"username": username}))
    return generatePolicy("user", 'Allow', event['methodArn'], {"username": username})
