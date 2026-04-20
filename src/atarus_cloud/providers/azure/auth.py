import subprocess
import json
from azure.identity import AzureCliCredential
from azure.mgmt.subscription import SubscriptionClient


def get_credential():
    try:
        cred = AzureCliCredential()
        cred.get_token("https://management.azure.com/.default")
        return cred
    except Exception as e:
        raise SystemExit(f"Azure authentication failed: {e}. Run 'az login' first.")


def _get_tenant_from_az_cli(subscription_id: str) -> str:
    try:
        result = subprocess.run(
            ["az", "account", "show", "--subscription", subscription_id, "-o", "json"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return data.get("tenantId", "")
    except Exception:
        pass
    return ""


def get_subscriptions(credential) -> list:
    try:
        client = SubscriptionClient(credential)
        subs = []
        for sub in client.subscriptions.list():
            sub_id = sub.subscription_id
            tenant_id = getattr(sub, "tenant_id", None) or ""
            if not tenant_id:
                try:
                    tenant_id = sub.as_dict().get("tenantId", "")
                except Exception:
                    tenant_id = ""
            if not tenant_id:
                tenant_id = _get_tenant_from_az_cli(sub_id)

            subs.append({
                "id": sub_id,
                "name": sub.display_name,
                "state": str(sub.state) if sub.state else "Unknown",
                "tenant_id": tenant_id,
            })
        return subs
    except Exception as e:
        raise SystemExit(f"Cannot list Azure subscriptions: {e}")


def get_default_subscription(credential) -> dict:
    subs = get_subscriptions(credential)
    enabled = [s for s in subs if "Enabled" in s["state"]]
    if not enabled:
        raise SystemExit("No enabled Azure subscriptions found.")
    return enabled[0]


def get_subscription_by_id(credential, subscription_id: str) -> dict:
    subs = get_subscriptions(credential)
    for s in subs:
        if s["id"] == subscription_id:
            return s
    raise SystemExit(f"Subscription {subscription_id} not found.")
