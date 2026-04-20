import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_session(profile: str = None, region: str = "us-east-1"):
    """Create an authenticated boto3 session"""
    try:
        if profile:
            session = boto3.Session(profile_name=profile, region_name=region)
        else:
            session = boto3.Session(region_name=region)

        sts = session.client("sts")
        identity = sts.get_caller_identity()

        return session, identity

    except NoCredentialsError:
        raise SystemExit("No AWS credentials found. Run 'aws configure' first.")
    except ClientError as e:
        raise SystemExit(f"AWS authentication failed: {e}")


def get_account_id(session) -> str:
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]


def get_account_alias(session) -> str:
    try:
        iam = session.client("iam")
        aliases = iam.list_account_aliases()["AccountAliases"]
        return aliases[0] if aliases else ""
    except Exception:
        return ""
