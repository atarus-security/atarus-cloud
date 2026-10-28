import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

# Used for STS, IAM and the region listing when the profile has no region of its own.
FALLBACK_REGION = "us-east-1"

NO_CREDENTIALS = (
    "No AWS credentials found. atarus-cloud reads the standard AWS credential chain "
    "(a profile from 'aws configure', AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or an "
    "instance or container role). Configure one and run again."
)


def get_session(profile: str = None, region: str = None):
    """Create the base boto3 session and confirm who we are with one STS call.

    Returns (session, identity). Exits with a one-line message, not a traceback,
    when there are no usable credentials.
    """
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        if session.region_name is None:
            session = boto3.Session(profile_name=profile, region_name=FALLBACK_REGION)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return session, identity
    except ProfileNotFound as e:
        raise SystemExit(f"AWS profile not found: {e}")
    except NoCredentialsError:
        raise SystemExit(NO_CREDENTIALS)
    except ClientError as e:
        raise SystemExit(f"AWS authentication failed: {e}")
    except BotoCoreError as e:
        raise SystemExit(f"AWS authentication failed: {e}")


def session_for_region(profile: str, region: str):
    """A session whose clients talk to one region."""
    return boto3.Session(profile_name=profile, region_name=region)


def enabled_regions(session) -> list:
    """Every region enabled for the account (opt-in regions only when enabled).
    Raises on failure so the caller can record the gap in the coverage table."""
    ec2 = session.client("ec2")
    regions = ec2.describe_regions()["Regions"]
    return sorted(r["RegionName"] for r in regions)


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
