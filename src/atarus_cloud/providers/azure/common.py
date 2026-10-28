"""Helpers shared by the Azure modules."""
from shlex import quote as q  # noqa: F401  (re-exported for the modules)


def resource_group_of(resource_id: str) -> str:
    """The resource group name inside an ARM resource id, or an empty string."""
    try:
        return resource_id.split("/resourceGroups/")[1].split("/")[0]
    except (AttributeError, IndexError):
        return ""


def sdk_missing(exc: ImportError) -> str:
    return f"Azure SDK package not installed ({exc}); install with pip install 'atarus-cloud[azure]'"
