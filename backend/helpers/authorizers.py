import json
import time
import urllib.request
import logging
from jose import jwk, jwt
from jose.utils import base64url_decode

from utils.generate_auth_policy import generatePolicy
from utils.username import get_username

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
    # token = event['token']
    # get the kid from the headers prior to verification
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
    logger.debug(claims)
    response["data"] = claims
    return response


def user_pool_auth(event, context):
    try:
        # Verify and get information from id_token
        idInformation = decode_verify_jwt(event['headers']['t2m-authtoken'])
        logger.info(idInformation)

        # Deny access if the account is not a Google account
        if idInformation['status']["code"] == 400:
            return generatePolicy(None, 'Deny', event['methodArn'])

        # Get principalId from idInformation
        principalId = idInformation["data"]["sub"]

    except ValueError as err:
        # Deny access if the token is invalid
        print(err)
        return generatePolicy(None, 'Deny', event['methodArn'])

    return generatePolicy(principalId, 'Allow', event['methodArn'], idInformation['data'])


def temp_token_auth(event, context):
    logger.info(event)
    try:
        payload = jwt.decode(event['headers']['t2m-temptoken'],
                             "#0wc-0-#@#14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=",
                             algorithms="HS256")
        username = payload.get("username")
        logger.info("Verified JWT for '{}'".format(username))
    except ValueError as err:
        logger.debug("Failed: Token verification failed.")
        return generatePolicy(None, 'Deny', event['methodArn'])

    return generatePolicy(username, 'Allow', event['methodArn'], {"username": username})


def guest_token_auth(event, context):
    logger.info(event)
    try:
        payload = jwt.decode(event['headers']['t2m-temptoken'],
                             "#0wc-0-#@#14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=",
                             algorithms="HS256")
        username = payload.get("username")
        username_obj = get_username(username)
        if len(username_obj) <= 0:
            logger.debug("Failed: User doesn't exist.")
            return generatePolicy(None, 'Deny', event['methodArn'])

        logger.info("Verified JWT for '{}'".format(username))
    except ValueError as err:
        logger.debug("Failed: Token verification failed.")
        return generatePolicy(None, 'Deny', event['methodArn'])

    return generatePolicy(username, 'Allow', event['methodArn'], {"username": username})


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


def ws_guest_token_auth(event, context):
    try:
        token = event.get("queryStringParameters", {}).get('token')
        payload = jwt.decode(token,
                             "#0wc-0-#@#14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=",
                             algorithms="HS256")
        username = payload.get("username")
        exp = payload.get("exp")
        username_obj = get_username(username)

        if len(username_obj) <= 0 :
            logger.debug("Failed: User doesn't exist.")
            return generatePolicy(None, 'Deny', event['methodArn'])

        if username_obj[0]["accessToken"] != token or exp <= int(time.time()):
            logger.debug("Failed: Invalid access token")
            return generatePolicy(None, 'Deny', event['methodArn'])

    except ValueError as err:
        logger.debug("Failed: Token verification failed.")
        return generatePolicy(None, 'Deny', event['methodArn'])

    return generatePolicy("user", 'Allow', event['methodArn'], {"username": username})

