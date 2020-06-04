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
    vault_addr = os.environ["VAULT_ADDR"]
    vault_region = os.environ['VAULT_AWS_REGION']
    vault_namespace = os.getenv('VAULT_NAMESPACE')
    vault_bucket = os.getenv('VAULT_BUCKET')
    vault_cert_loc = os.getenv('VAULT_SERVER_CERT')
    vault_role = os.getenv('VAULT_ROLE_ARN')

    path = event["queryStringParameters"]['path']
    role = event["queryStringParameters"]['role']

    #session_assumed = aws_session(role_arn=vault_role, session_name='my_vault_lambda')
    session_regular = aws_session()

    client = hvac.Client(url=vault_addr,
                         namespace=vault_namespace,
                         verify=False
                         )

    creds = session_regular.get_credentials().get_frozen_credentials()

    client.auth.aws.iam_login(
        access_key=creds.access_key,
        secret_key=creds.secret_key,
        session_token=creds.token,
        role=role,
        use_token=True,
        region=vault_region
    )

    secret_version_response = client.secrets.kv.v2.read_secret_version(
        mount_point='kv',
        path=path
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
