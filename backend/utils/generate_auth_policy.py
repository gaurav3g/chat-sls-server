def generatePolicy(principalId, effect, methodArn, data=None):
    authResponse = {'principalId': principalId}

    if effect and methodArn:
        policyDocument = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': 'FirstStatement',
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': methodArn
                }
            ]
        }

        authResponse['policyDocument'] = policyDocument

    if data is not None:
        authResponse['context'] = data

    return authResponse
