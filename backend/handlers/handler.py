import boto3
import json
import jwt
import logging
import time
import uuid
from lambda_decorators import cors_headers

from utils.json_encoder import json_encoder
from utils.user_attr_formatter import formatter
from utils.user import get_user_by_email
from helpers.authorizers import ws_token_auth
from utils.jwt_utils import jwt_decode
from helpers.db import db, firestore


logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)


dynamodb = boto3.resource("dynamodb")
cognito_client = boto3.client('cognito-idp')


def _get_body(event):
    try:
        return json.loads(event.get("body", ""))
    except:
        logger.debug("event body could not be JSON decoded.")
        return {}


def _get_response(status_code, body):
    if not isinstance(body, str):
        body = json.dumps(body, default=json_encoder)

    if status_code != 200:
        logger.debug('Failed: {}'.format(body))

    return {"statusCode": status_code, "body": body}


def _send_to_connection(connection_id, data, event):
    gateway_client = boto3.client("apigatewaymanagementapi",
                              endpoint_url="https://" + event["requestContext"][
                                  "domainName"] +
                                           "/" + event["requestContext"]["stage"])
    try:
        return gateway_client.post_to_connection(ConnectionId=connection_id,
                                         Data=json.dumps(data, default=json_encoder).encode('utf-8'))
    except GoneException:
        return false


def connection_manager(event, context):
    # logger.info(event)
    connectionID = event["requestContext"].get("connectionId")
    token = event.get("queryStringParameters", {}).get("token")

    if event["requestContext"]["eventType"] == "CONNECT":
        # logger.info("Connect requested (CID: {}, Token: {})" \
        #             .format(connectionID, token))

        # Ensure connectionID and token are set
        if not connectionID:
            logger.error("Failed: connectionId value not set.")
            return _get_response(500, "connectionId value not set.")
        if not token:
            return _get_response(400, "token query parameter not provided.")

        if event.get("requestContext", {}).get("authorizer") is not None:
            email = event.get("requestContext", {}).get("authorizer", {}).get("email")
        else:
            user_obj = get_user_by_email(jwt_decode(token)['email'])
            if len(user_obj) > 0:
                email = user_obj[0]["email"]

        # Add connectionID to the database
        user_ref = db.collection(u'users').document(email)
        user_ref.update({'connectionID': connectionID})

        connection_ref = db.collection(u'connections').document(connectionID)
        connection_ref.set({'email': email})

        return _get_response(200, "Connect successful.")

    elif event["requestContext"]["eventType"] == "DISCONNECT":
        logger.info("Disconnect requested (CID: {})".format(connectionID))

        # Ensure connectionID is set
        if not connectionID:
            logger.error("Failed: connectionId value not set.")
            return _get_response(500, "connectionId value not set.")

        # Remove the connectionID from the database
        connections_ref = db.collection(u'connections').document(connectionID).get()
        if connections_ref.exists:
            conn_obj = connections_ref.to_dict()

            email = conn_obj['email']

            user_ref = db.collection(u'users').document(email)
            user_ref.update({'connectionID': ''})

            db.collection(u'connections').document(connectionID).delete()
            return _get_response(200, "Disconnect successful.")
        else:
            return _get_response(400, "Invalid connection id.")
    else:
        logger.error("Connection manager received unrecognized eventType '{}'" \
                     .format(event["requestContext"]["eventType"]))
        return _get_response(500, "Unrecognized eventType.")


def default_message(event, context):
    """
    Send back error when unrecognized WebSocket action is received.
    """
    logger.info("Unrecognized WebSocket action received.")
    return _get_response(400, "Unrecognized WebSocket action.")


def get_recent_messages(event, context):
    body = _get_body(event)
    connectionID = event["requestContext"].get("connectionId")
    logger.info("Retrieving most recent messages for CID '{}'" \
                .format(connectionID))

    # Ensure connectionID is set
    if not connectionID:
        logger.error("Failed: connectionId value not set.")
        return _get_response(500, "connectionId value not set.")

    LastEvaluatedKeyIn = None
    if "LastEvaluatedKey" in body:
        LastEvaluatedKeyIn = body["LastEvaluatedKey"]

    limit = 100
    try:
        if "limit" in body and body["limit"] < 60:
            limit = body["limit"]
    except ValueError:
        logger.error("Error in getting limit")

    logger.info(LastEvaluatedKeyIn)

    messages = []
    if LastEvaluatedKeyIn is not None:
        query = db.collection(u'rooms').\
            document(u'general').collection(u'messages').\
            order_by(u'created_at', direction=firestore.Query.DESCENDING).\
            limit(limit).start_after(LastEvaluatedKeyIn).stream()
        print(response)
    else:
        query = db.collection(u'rooms'). \
            document(u'general').collection(u'messages'). \
            order_by(u'created_at', direction=firestore.Query.DESCENDING).\
            start_after("54zvuhw1yi80bVMU5ZCd").limit(limit).stream()

    LastEvaluatedKeyOut = None
    for doc in query:
        LastEvaluatedKeyOut = doc.to_dict()
        message = doc.to_dict()
        messages.append({"email": message["email"],
                         "content": message["content"],
                         "created_at": message["created_at"]})

    messages.reverse()
    parsed_user = {}

    def map_function(x):
        if x['email'] not in parsed_user:
            parsed_user[x['email']] = get_user_by_email(x['email'])[0]

        resp = {**x, "sender": {"username": parsed_user[x['email']]["username"],
                                "email": parsed_user[x['email']]["email"]}}
        if "email" in resp:
            del resp['email']

        return resp

    messages = list(map(map_function, messages))
    logger.info(messages)

    # Send them to the client who asked for it
    data = {"messages": messages}

    if LastEvaluatedKeyOut is not None:
        data["LastEvaluatedKey"] = LastEvaluatedKeyOut

    _send_to_connection(connectionID, data, event)

    return _get_response(200, "Sent recent messages to '{}'." \
                         .format(connectionID))


def send_message(event, context):
    body = _get_body(event)
    if not isinstance(body, dict):
        return _get_response(400, "Message body not in dict format.")
    for attribute in ["token", "content"]:
        if attribute not in body:
            return _get_response(400, "'{}' not in message dict" \
                                 .format(attribute))

    # Verify the token
    try:
        auth_data = ws_token_auth(body["token"], body["auth"] if "auth" in body else 0)
        if auth_data['effect'] == "Deny":
            return _get_response(400, "Token verification failed.")

        email = auth_data['data']['email']
        username = auth_data['data']['preferred_username']
    except:
        return _get_response(400, "Token verification failed.")

    table = dynamodb.Table("serverless-chat_Messages")
   # Add the new message to the database
    timestamp = int(time.time())
    content = body["content"]
    table_ref = db.collection(u'rooms').document(u'general').collection(u'messages')
    table_ref.add({"created_at": timestamp,"email": email, "content": content})

    # Get all current connections
    table = dynamodb.Table("serverless-chat_Connections")
    response = table.scan(ProjectionExpression="ConnectionID")
    items = response.get("Items", [])
    connections = db.collection(u'connections').get()
    connections = list(map(lambda doc: doc.id, connections))

    # Send the message data to all connections
    message = {"sender": {"username": username, "email": email},
               "content": content, "created_at": timestamp}
    logger.debug("Broadcasting message: {}".format(message))
    data = {"messages": [message], "end": 1}
    for connectionID in connections:
        _send_to_connection(connectionID, data, event)
    return _get_response(200, "Message sent to {} connections." \
                         .format(len(connections)))


def ping(event, context):
    logger.info("Ping requested.")
    return _get_response(200, "PONG!")


def user_migrate(event, context):
    logger.info("User migaration triggered")

    try:
        user_data = event['request']['userAttributes']
    except:
        logger.info("failed to get user data")

    try:
        if user_data is not None:
            db.collection("users").add({"email": user_data["email"],
                                        "uId": user_data["sub"],
                                        "email_verified": user_data["email_verified"],
                                        "username": user_data["preferred_username"],
                                        "Gender": user_data["gender"]
                                        });
    except:
        logger.info("Failed to put user object!")

    return event


@cors_headers
def set_conversation(event, context, items=None):
    body = _get_body(event)
    if not isinstance(body, dict):
        return _get_response(400, "Request body not in dict format.")
    # for attribute in ["token", "participant"]:
    for attribute in ["participant"]:
        if attribute not in body:
            return _get_response(400, "'{}' not in request dict" \
                                 .format(attribute))

    try:
        user = cognito_client.get_user(AccessToken=event['headers']['t2m-authtoken'])
        user_data = formatter(user["UserAttributes"])
        # logger.info(user_data)
        # payload = jwt.decode(body["token"],
        #                      "#0wc-0-#@#14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=",
        #                      algorithms="HS256")
        username = user_data["preferred_username"]
        logger.info("Verified JWT for '{}'".format(username))
    except:
        return _get_response(400, "Token verification failed.")

    if user_data["email"] == body["participant"]:
        return _get_response(400, "Can't create room.")

    user_table = dynamodb.Table("serverless-chat_Users")
    createFlag = True

    user_response = user_table.query(KeyConditionExpression="email = :email",
                                     ExpressionAttributeValues={
                                         ":email": body['participant']},
                                     Limit=1)
    user_obj = user_response.get("Items", [])
    if len(user_obj) > 0:
        participant = {"username": user_obj[0]["username"],
                       "email": user_obj[0]["email"],
                       "uId": user_obj[0]['uId']}
    else:
        return _get_response(400, "User not found.")

    # Create unique data for room
    room_title = "_".join(sorted([user_data["email"], participant["email"]]))
    room_url = str(uuid.uuid5(uuid.NAMESPACE_DNS, room_title))

    conversation_table = dynamodb.Table("serverless-chat_Personal_Room")
    conversation_response = conversation_table.query(
        KeyConditionExpression="RoomId = :room_id",
        ExpressionAttributeValues={":room_id": room_title},
        Limit=1)
    conversation_items = conversation_response.get("Items", [])

    if len(conversation_items):
        room_data = conversation_items[0]
    else:
        try:
            room_data = {"RoomId": room_title,
                         "created_by": user_data["email"],
                         "created_at": int(time.time()),
                         "updated_at": int(time.time()),
                         "deleted_at": 0,
                         "participant1": user_data["email"],
                         "participant2": participant["email"],
                         "url": room_url
                         }
            conversation_table.put_item(Item=room_data)
        except:
            logger.info("Failed to create chat-room!")
    logger.info(room_data)
    return _get_response(200, room_data)
