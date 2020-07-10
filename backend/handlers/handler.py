import boto3
import json
import jwt
import logging
import time
import uuid
from lambda_decorators import cors_headers

from utils.json_encoder import json_encoder
from utils.user_attr_formatter import formatter
from utils.username import get_username

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
    logger.info("WE ENTERED {}".format(event))
    connectionID = event["requestContext"].get("connectionId")
    token = event.get("queryStringParameters", {}).get("token")

    if event["requestContext"]["eventType"] == "CONNECT":
        logger.info("Connect requested (CID: {}, Token: {})" \
                    .format(connectionID, token))

        # Ensure connectionID and token are set
        if not connectionID:
            logger.error("Failed: connectionId value not set.")
            return _get_response(500, "connectionId value not set.")
        if not token:
            return _get_response(400, "token query parameter not provided.")

        # Verify the token
        try:
            payload = jwt.decode(token,
                                 "#0wc-0-#@#14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=",
                                 algorithms="HS256")
            logger.info("Verified JWT for '{}'".format(payload.get("username")))
        except:
            return _get_response(400, "Token verification failed.")

        # Add connectionID to the database
        table = dynamodb.Table("serverless-chat_Connections")
        table.put_item(Item={"ConnectionID": connectionID})
        return _get_response(200, "Connect successful.")

    elif event["requestContext"]["eventType"] == "DISCONNECT":
        logger.info("Disconnect requested (CID: {})".format(connectionID))

        # Ensure connectionID is set
        if not connectionID:
            logger.error("Failed: connectionId value not set.")
            return _get_response(500, "connectionId value not set.")

        # Remove the connectionID from the database
        table = dynamodb.Table("serverless-chat_Connections")
        table.delete_item(Key={"ConnectionID": connectionID})
        return _get_response(200, "Disconnect successful.")

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
    """
    Return the 10 most recent chat messages.
    """
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

    # Get the 10 most recent chat messages
    table = dynamodb.Table("serverless-chat_Messages")

    if LastEvaluatedKeyIn is not None:
        response = table.query(KeyConditionExpression="Room = :room",
                               ExpressionAttributeValues={":room": "general"},
                               Limit=limit, ExclusiveStartKey={'Index': LastEvaluatedKeyIn, 'Room': 'general'},
                               ScanIndexForward=False)
    else:
        response = table.query(KeyConditionExpression="Room = :room",
                               ExpressionAttributeValues={":room": "general"},
                               Limit=limit, ScanIndexForward=False)

    items = response.get("Items", [])

    # Extract the relevant data and order chronologically
    messages = [{"sender": x["Username"], "content": x["Content"], "created_at": x["Timestamp"]}
                for x in items]
    messages.reverse()
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
    # Send them to the client who asked for it
    data = {"messages": messages}

    if response.get('LastEvaluatedKey', None) is not None:
        data["LastEvaluatedKey"] = int(response.get('LastEvaluatedKey', None).get("Index", None))

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
        payload = jwt.decode(body["token"],
                             "#0wc-0-#@#14e8rbk#bke_9rg@nglfdc3&6z_r6nx!q6&3##l=",
                             algorithms="HS256")
        username = payload.get("username")
        logger.info("Verified JWT for '{}'".format(username))
        exp = payload.get("exp")
        username_obj = get_username(username)

        if len(username_obj) <= 0:
            return _get_response(400, "User doesn't exist.")

        if username_obj[0]["accessToken"] != body["token"] or exp <= int(time.time()):
            return _get_response(400, "Invalid access token.")
    except:
        return _get_response(400, "Token verification failed.")

    # Get the next message index
    # (Note: there is technically a race condition where two
    # users post at the same time and use the same index, but
    # accounting for that is outside the scope of this project)
    table = dynamodb.Table("serverless-chat_Messages")
    response = table.query(KeyConditionExpression="Room = :room",
                           ExpressionAttributeValues={":room": "general"},
                           Limit=1, ScanIndexForward=False)
    items = response.get("Items", [])
    index = items[0]["Index"] + 1 if len(items) > 0 else 0

    # Add the new message to the database
    timestamp = int(time.time())
    content = body["content"]
    table.put_item(Item={"Room": "general", "Index": index,
                         "Timestamp": timestamp, "Username": username,
                         "Content": content})

    # Get all current connections
    table = dynamodb.Table("serverless-chat_Connections")
    response = table.scan(ProjectionExpression="ConnectionID")
    items = response.get("Items", [])
    connections = [x["ConnectionID"] for x in items if "ConnectionID" in x]

    # Send the message data to all connections
    message = {"sender": username, "content": content, "created_at": timestamp}
    logger.debug("Broadcasting message: {}".format(message))
    data = {"messages": [message], "end": 1}
    for connectionID in connections:
        _send_to_connection(connectionID, data, event)
    return _get_response(200, "Message sent to {} connections." \
                         .format(len(connections)))


def ping(event, context):
    """
    Sanity check endpoint that echoes back 'PONG' to the sender.
    """
    logger.info("Ping requested.")
    return _get_response(200, "PONG!")


def user_migrate(event, context):
    logger.info("User migaration triggered")

    try:
        user_data = event['request']['userAttributes']
    except:
        logger.info("failed to get user data")

    table = dynamodb.Table("serverless-chat_Users")
    try:
        if user_data is not None:
            table.put_item(Item={"Email": user_data["email"], "uId": user_data["sub"],
                                 "email_verified": user_data["email_verified"],
                                 "Username": user_data["preferred_username"],
                                 "Gender": user_data["gender"]
                                 })
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

    user_response = user_table.query(KeyConditionExpression="Email = :email",
                                     ExpressionAttributeValues={
                                         ":email": body['participant']},
                                     Limit=1)
    user_obj = user_response.get("Items", [])
    if len(user_obj) > 0:
        participant = {"username": user_obj[0]["Username"],
                       "email": user_obj[0]["Email"],
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
