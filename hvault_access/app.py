import json
import boto3
import hvac
import os


def aws_session(role_arn=None, session_name='my_session'):
    """
    If role_arn is given assumes a role and returns boto3 session
    otherwise return a regular session with the current IAM user/role
    """
    if role_arn:
        client = boto3.client('sts')
        response = client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'])
        return session
    else:
        return boto3.Session()


def lambda_handler(event, context):
    VAULT_ADDR = os.environ["VAULT_ADDR"]
    VAULT_HEADER_VALUE = os.environ["VAULT_HEADER_VALUE"]
    ROLE_ARN = os.environ['ROLE_ARN']
    SECRET_PATH = os.environ['SECRET_PATH']
    AWS_REGION = os.environ['C_AWS_REGION']

    path = event["queryStringParameters"]['path'] or SECRET_PATH

    # session = aws_session(role_arn=ROLE_ARN, session_name='my_vault_lambda')
    # session_regular = aws_session()

    client = hvac.Client(url=VAULT_ADDR,
                         verify=False)

    session = boto3.Session()
    creds = session.get_credentials().get_frozen_credentials()
    client.auth_aws_iam(
        creds.access_key,
        creds.secret_key,
        creds.token,
        region=AWS_REGION,
        role=ROLE_ARN,
        header_value=VAULT_HEADER_VALUE,
        use_token=True
    )

    secret_version_response = client.secrets.kv.v2.read_secret_version(
        mount_point='kv',
        path=path,
    )

    secret_dict = secret_version_response['data']['data']

    date = secret_version_response['data']['metadata']['created_time']
    ver = secret_version_response['data']['metadata']['version']
    value = ','.join(secret_dict.values())

    return {
        "statusCode": 200,
        "body": json.dumps({
            "secret": value,
            "creation_time": date,
            "version": ver
        }),
    }
