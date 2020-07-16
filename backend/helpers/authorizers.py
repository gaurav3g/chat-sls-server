import json
import time
import urllib.request
import logging
import boto3
from jose import jwk, jwt
from jose.utils import base64url_decode

from utils.generate_auth_policy import generatePolicy
from utils.user import get_user_by_email
from utils.jwt_utils import jwt_decode
from utils.user_attr_formatter import formatter

cip_client = boto3.client('cognito-idp')

logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)

region = 'ap-south-1'
userpool_id = 'ap-south-1_0doORXgFW'
app_client_id = '34gacun9jhtempvi5bb4gtln4q'
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region,
                                                                                  userpool_id)
# instead of re-downloading the public keys every time
# we download them only on cold start
# https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
with urllib.request.urlopen(keys_url) as f:
    response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']


def decode_verify_jwt(token):
    response = {
        "status": {
            "code": 200,
            "message": ""
        },
        "data": {}
    }
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        logger.error('Public key not found in jwks.json')
        response["status"]["code"] = 400
        response["status"]["message"] = "Public key not found in jwks.json"
        return response
    # construct the public key
    public_key = jwk.construct(keys[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        logger.error('Signature verification failed')
        response["status"]["code"] = 400
        response["status"]["message"] = "Signature verification failed"
        return response
    logger.info('Signature successfully verified')
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        logger.debug('Token is expired')
        response["status"]["code"] = 400
        response["status"]["message"] = "Token is expired"
        return response

    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims['client_id'] != app_client_id:
        logger.error('Token was not issued for this audience')
        response["status"]["code"] = 400
        response["status"]["message"] = "Token was not issued for this audience"
        return response

    # now we can use the claims
    response["data"] = claims
    return response


def token_pool_auth(token):
    result = {"status": False, "data": {}}
    try:
        idInformation = decode_verify_jwt(token)

        if idInformation['status']["code"] == 200:
            result["status"] = True
            result["data"] = idInformation['data']

    except ValueError as err:
        logger.debug("Failed: invalid User pool token")

    return result


def user_pool_auth(event, context):
    try:
        token_auth = token_pool_auth(event['headers']['t2m-authtoken'])

        if not token_auth["status"]:
            return generatePolicy(None, 'Deny', event['methodArn'])

        # Get principalId from idInformation
        principalId = token_auth["data"]["sub"]

    except ValueError as err:
        return generatePolicy(None, 'Deny', event['methodArn'])

    return generatePolicy(principalId, 'Allow', event['methodArn'], token_auth['data'])


def temp_token_auth(event, context):
    try:
        payload = jwt.decode(event['headers']['t2m-temptoken'],
                             "#0wc-0-#@#14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=",
                             algorithms="HS256")
        email = payload.get("email")
    except ValueError as err:
        logger.debug("Failed: Token verification failed.")
        return generatePolicy(None, 'Deny', event['methodArn'])

    return generatePolicy(email, 'Allow', event['methodArn'], {"email": email})


def guest_token_auth(event, context):
    logger.info(event)
    try:
        payload = jwt.decode(event['headers']['t2m-temptoken'],
                             "#0wc-0-#@#14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=",
                             algorithms="HS256")
        email = payload.get("email")
        username_obj = get_user_by_email(email)
        if len(username_obj) <= 0:
            logger.debug("Failed: User doesn't exist.")
            return generatePolicy(None, 'Deny', event['methodArn'])

    except ValueError as err:
        logger.debug("Failed: Token verification failed.")
        return generatePolicy(None, 'Deny', event['methodArn'])

    return generatePolicy(email, 'Allow', event['methodArn'], {"email": email})


# def ws_temp_token_auth(event, context):
#     try:
#         payload = jwt.decode(event.get("queryStringParameters", {}).get('token'),
#                              "#0wc-0-#@#14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=",
#                              algorithms="HS256")
#         username = payload.get("username")
#         logger.info("Verified JWT for '{}'".format(username))
#     except ValueError as err:
#         logger.debug("Failed: Token verification failed.")
#         return generatePolicy(None, 'Deny', event['methodArn'])
#
#     logger.info(generatePolicy("user", 'Allow', event['methodArn'], {"username": username}))
#     return generatePolicy("user", 'Allow', event['methodArn'], {"username": username})

def ws_token_auth(token, auth_flag=0):
    result = {"user": None, "effect": "Deny", "data": None}
    if token is None:
        return result

    if auth_flag:
        token_auth = token_pool_auth(token)

        if token_auth["status"]:
            result["user"] = token_auth["data"]["sub"]
            result["effect"] = "Allow"
            try:
                user = cip_client.get_user(AccessToken=token)
                user_data = formatter(user["UserAttributes"])
                result["data"] = user_data
            except:
                logger.debug("Failed: Unable to fetch user data")
    else:
        payload = jwt_decode(token)
        email = payload.get("email")
        exp = payload.get("exp")

        username_obj = get_user_by_email(email)

        if len(username_obj) > 0 and username_obj[0]["accessToken"] == token \
                and exp > int(time.time()):
            result["user"] = "user"
            result["effect"] = "Allow"
            result["data"] = {"email": email, "preferred_username": username_obj[0]["Username"]}

    return result


def ws_guest_token_auth(event, context):
    result = {"user": None, "effect": "Deny",
              "methodArn": event['methodArn'], "data": None}
    token = event.get("queryStringParameters", {}).get('token')
    authFlag = 0
    try:
        if event.get("queryStringParameters", {}).get('auth'):
            authFlag = event.get("queryStringParameters", {}).get('auth')
    except:
        logger.debug("Failed: unable to get auth flag")

    try:
        auth_resp = ws_token_auth(token, authFlag)
        return generatePolicy(auth_resp["user"], auth_resp["effect"],
                              event['methodArn'], auth_resp["data"])
    except:
        logger.debug("Failed: Token WS verification failed.")
        return generatePolicy(result["user"], result["effect"],
                              event['methodArn'], result["data"])
    # if authFlag:
    #     token_auth = token_pool_auth(token)
    #
    #     if token_auth["status"]:
    #         result["user"] = token_auth["data"]["sub"]
    #         result["effect"] = "Allow"
    #         try:
    #             user = cip_client.get_user(AccessToken=token)
    #             user_data = formatter(user["UserAttributes"])
    #             result["data"] = user_data
    #             # logger.info(user_data)
    #         except:
    #             logger.debug("Failed: Unable to fetch user data")
    # else:
    #     payload = jwt_decode(token)
    #     email = payload.get("email")
    #     exp = payload.get("exp")
    #
    #     username_obj = get_user_by_email(email)
    #
    #     if len(username_obj) > 0 and username_obj[0]["accessToken"] == token \
    #             and exp > int(time.time()):
    #         result["user"] = "user"
    #         result["effect"] = "Allow"
    #         result["data"] = {"email": email}

    # return generatePolicy(result["user"], result["effect"], result['methodArn'], result["data"])
