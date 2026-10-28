"""Helpers shared by the AWS modules."""
from shlex import quote as q  # noqa: F401  (re-exported for the modules)


def region_of(session) -> str:
    """The region a session's clients talk to, for the coverage table and findings."""
    return getattr(session, "region_name", None) or "unknown"


def error_code(exc: BaseException) -> str:
    """The AWS error code carried by a botocore ClientError, or an empty string."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""
