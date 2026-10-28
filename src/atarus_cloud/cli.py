import importlib.util

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from atarus_cloud import __version__
from atarus_cloud.runner import CloudRunner, SCOPE_GLOBAL, SCOPE_REGIONAL
from atarus_cloud.models import SUBSCRIPTION
from atarus_cloud.providers.aws import auth as aws_auth
from atarus_cloud.providers.aws import iam, s3, ec2, cloudtrail, rds, vpc, lambda_fn, kms, secrets
from atarus_cloud.providers.azure import auth as az_auth
from atarus_cloud.providers.azure import identity as az_identity, storage as az_storage, network as az_network, compute as az_compute
from atarus_cloud.providers.azure import keyvault as az_keyvault, sql as az_sql, cosmosdb as az_cosmosdb
from atarus_cloud.analysis import attack_paths, exec_summary, compliance
from atarus_cloud.reports import html, json_export, pdf, remediation

console = Console()

VERSION = __version__

BANNER = f"""
   ╔═╗╔╦╗╔═╗╦═╗╦ ╦╔═╗  ╔═╗╦  ╔═╗╦ ╦╔╦╗
   ╠═╣ ║ ╠═╣╠╦╝║ ║╚═╗  ║  ║  ║ ║║ ║ ║║
   ╩ ╩ ╩ ╩ ╩╩╚═╚═╝╚═╝  ╚═╝╩═╝╚═╝╚═╝═╩╝
   Atarus Offensive Security | v{VERSION}
"""

# (display name, key, run function, service label in the coverage table, scope)
AWS_MODULES = [
    ("IAM audit", "iam", iam.run, "IAM", SCOPE_GLOBAL),
    ("S3 audit", "s3", s3.run, "S3", SCOPE_GLOBAL),
    ("EC2 audit", "ec2", ec2.run, "EC2", SCOPE_REGIONAL),
    ("CloudTrail audit", "cloudtrail", cloudtrail.run, "CloudTrail", SCOPE_REGIONAL),
    ("RDS audit", "rds", rds.run, "RDS", SCOPE_REGIONAL),
    ("VPC audit", "vpc", vpc.run, "VPC", SCOPE_REGIONAL),
    ("Lambda audit", "lambda", lambda_fn.run, "Lambda", SCOPE_REGIONAL),
    ("KMS audit", "kms", kms.run, "KMS", SCOPE_REGIONAL),
    ("Secrets Manager audit", "secrets", secrets.run, "SecretsManager", SCOPE_REGIONAL),
]

AZURE_MODULES = [
    ("Identity audit", "identity", az_identity.run, "Identity", SCOPE_REGIONAL),
    ("Storage audit", "storage", az_storage.run, "Storage", SCOPE_REGIONAL),
    ("Network audit", "network", az_network.run, "Network", SCOPE_REGIONAL),
    ("Compute audit", "compute", az_compute.run, "Compute", SCOPE_REGIONAL),
    ("Key Vault audit", "keyvault", az_keyvault.run, "KeyVault", SCOPE_REGIONAL),
    ("SQL audit", "sql", az_sql.run, "SQL", SCOPE_REGIONAL),
    ("Cosmos DB audit", "cosmosdb", az_cosmosdb.run, "CosmosDB", SCOPE_REGIONAL),
]

# Import names of the Azure SDK packages the Azure provider needs, with the pip
# name to show when one is missing. Installed with: pip install 'atarus-cloud[azure]'
AZURE_SDK_PACKAGES = [
    ("azure.identity", "azure-identity"),
    ("azure.mgmt.subscription", "azure-mgmt-subscription"),
    ("azure.mgmt.authorization", "azure-mgmt-authorization"),
    ("azure.mgmt.storage", "azure-mgmt-storage"),
    ("azure.mgmt.network", "azure-mgmt-network"),
    ("azure.mgmt.compute", "azure-mgmt-compute"),
    ("azure.mgmt.keyvault", "azure-mgmt-keyvault"),
    ("azure.mgmt.sql", "azure-mgmt-sql"),
    ("azure.mgmt.cosmosdb", "azure-mgmt-cosmosdb"),
]

AZURE_INSTALL_HINT = "Install the Azure extra: pip install 'atarus-cloud[azure]'"
PDF_INSTALL_HINT = "Install the PDF extra and the Pango system libraries: pip install 'atarus-cloud[pdf]' (see README, Install)"


def missing_azure_packages() -> list:
    """pip names of the Azure SDK packages that are not importable."""
    missing = []
    for import_name, pip_name in AZURE_SDK_PACKAGES:
        try:
            found = importlib.util.find_spec(import_name) is not None
        except (ImportError, ValueError):
            found = False
        if not found:
            missing.append(pip_name)
    return missing


def pdf_available() -> bool:
    try:
        return importlib.util.find_spec("weasyprint") is not None
    except (ImportError, ValueError):
        return False


def _split_list(value: str) -> list:
    return [s.strip() for s in value.split(",") if s.strip()] if value else []


def _parse_regions(values) -> list:
    """--region may be repeated or comma separated. Empty or 'all' means every enabled region."""
    regions = []
    for v in values or ():
        regions.extend(_split_list(v))
    regions = [r.lower() for r in regions]
    if not regions or "all" in regions:
        return []
    seen = []
    for r in regions:
        if r not in seen:
            seen.append(r)
    return seen


@click.command()
@click.option("-p", "--provider", default="aws", type=click.Choice(["aws", "azure"]), help="Cloud provider")
@click.option("--profile", default=None, help="AWS profile name (AWS only)")
@click.option("--subscription", default=None, help="Azure subscription ID (Azure only)")
@click.option("--region", "regions", multiple=True,
              help="AWS region to check; repeat or comma-separate for several. Default: every region enabled for the account. "
                   "Regions you leave out are listed as not checked and the score is withheld.")
@click.option("-o", "--output", default="./output", help="Output directory")
@click.option("--format", "out_format", default="html", type=click.Choice(["html", "json", "pdf", "all"]), help="Report format")
@click.option("--remediation-script", is_flag=True,
              help="Also write remediation-<account>.sh: every command commented out and every value quoted, "
                   "file mode 0644. Review it line by line before running anything from it.")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--skip", default="", help="Comma-separated modules to skip (recorded as not run)")
@click.option("--only", default="", help="Comma-separated modules to run exclusively (the rest are recorded as not run)")
@click.option("--list-modules", is_flag=True, help="List available modules and exit")
@click.version_option(version=VERSION, prog_name="atarus-cloud")
def main(provider, profile, subscription, regions, output, out_format, remediation_script, verbose, skip, only, list_modules):
    """atarus-cloud: read-only cloud configuration review by Atarus Offensive Security"""

    if list_modules:
        table = Table(title="Available modules")
        table.add_column("Provider", style="bold yellow")
        table.add_column("Key", style="bold cyan")
        table.add_column("Scope")
        table.add_column("Description")
        for name, key, _, _, scope in AWS_MODULES:
            table.add_row("aws", key, scope, name)
        for name, key, _, _, scope in AZURE_MODULES:
            table.add_row("azure", key, SUBSCRIPTION, name)
        console.print(table)
        return

    skip_list = _split_list(skip)
    only_list = _split_list(only)
    known = {key for _, key, _, _, _ in (AWS_MODULES if provider == "aws" else AZURE_MODULES)}
    unknown = [k for k in skip_list + only_list if k.lower() not in known]
    if unknown:
        raise click.UsageError(f"Unknown module(s) for {provider}: {', '.join(unknown)}. See --list-modules.")

    if provider == "azure":
        missing = missing_azure_packages()
        if missing:
            raise click.UsageError(
                f"Azure support is not installed (missing {', '.join(missing)}). {AZURE_INSTALL_HINT}"
            )

    if out_format == "pdf" and not pdf_available():
        raise click.UsageError(f"PDF export is not installed. {PDF_INSTALL_HINT}, or use --format html or json.")
    if out_format == "all" and not pdf_available():
        console.print(f"[yellow]PDF export is not installed; writing HTML and JSON only.[/] {escape(PDF_INSTALL_HINT)}")

    console.print(BANNER, style="bold red")

    if provider == "aws":
        _run_aws(profile, _parse_regions(regions), skip_list, only_list, verbose, output, out_format, remediation_script)
    elif provider == "azure":
        _run_azure(subscription, skip_list, only_list, verbose, output, out_format, remediation_script)


def _select_regions(base_session, requested: list):
    """Decide which regions to check and which to list as not checked.

    Returns (regions_to_check, regions_not_checked, enumeration_error). With no
    explicit list, every enabled region is checked. With a list, the enabled
    regions outside it are recorded as not checked. If the region listing itself
    fails, the gap is recorded so the coverage cannot read as complete.
    """
    not_checked = []
    enumeration_error = None
    try:
        enabled = aws_auth.enabled_regions(base_session)
    except Exception as e:
        enabled = None
        enumeration_error = e

    if requested:
        to_check = list(requested)
        if enabled is not None:
            for r in enabled:
                if r not in to_check:
                    not_checked.append({"region": r, "reason": "not in the --region list"})
            unknown = [r for r in to_check if r not in enabled]
            for r in unknown:
                console.print(f"[yellow]Region {escape(r)} is not enabled for this account; checking it anyway as requested.[/]")
    elif enabled is not None:
        to_check = enabled
    else:
        fallback = base_session.region_name or aws_auth.FALLBACK_REGION
        to_check = [fallback]
        not_checked.append({
            "region": "all other regions",
            "reason": f"could not list enabled regions (ec2:DescribeRegions): {enumeration_error}",
        })
    return to_check, not_checked, enumeration_error


def _run_aws(profile, requested_regions, skip_list, only_list, verbose, output, out_format, remediation_script):
    console.print("[bold white]Authenticating to AWS...[/]")
    base_session, identity = aws_auth.get_session(profile=profile)
    account_id = identity["Account"]
    user_arn = identity["Arn"]
    console.print(f"[bold white]Account:[/] {escape(str(account_id))}")
    console.print(f"[bold white]Identity:[/] {escape(str(user_arn))}")

    regions, not_checked, enumeration_error = _select_regions(base_session, requested_regions)
    if enumeration_error is not None:
        console.print(f"[yellow]Could not list enabled regions:[/] {escape(str(enumeration_error))}")

    sessions = {r: aws_auth.session_for_region(profile, r) for r in regions}
    runner = CloudRunner(
        provider="aws", sessions=sessions, global_session=base_session,
        verbose=verbose, skip=skip_list, only=only_list,
    )
    runner.result.account_id = account_id
    runner.result.account_alias = aws_auth.get_account_alias(base_session)
    runner.result.regions_not_checked = not_checked

    for name, key, func, service, scope in AWS_MODULES:
        runner.register(name, key, func, service=service, scope=scope)

    _finalize(runner, output, out_format, remediation_script)


def _run_azure(subscription_id, skip_list, only_list, verbose, output, out_format, remediation_script):
    console.print("[bold white]Authenticating to Azure...[/]")
    credential = az_auth.get_credential()

    if subscription_id:
        sub = az_auth.get_subscription_by_id(credential, subscription_id)
    else:
        sub = az_auth.get_default_subscription(credential)

    console.print(f"[bold white]Tenant:[/] {escape(str(sub['tenant_id']))}")
    console.print(f"[bold white]Subscription:[/] {escape(str(sub['id']))}")
    console.print(f"[bold white]Name:[/] {escape(str(sub['name']))}")

    azure_session = {
        "credential": credential,
        "subscription_id": sub["id"],
        "tenant_id": sub["tenant_id"],
    }

    runner = CloudRunner(
        provider="azure", sessions={SUBSCRIPTION: azure_session},
        verbose=verbose, skip=skip_list, only=only_list,
    )
    runner.result.account_id = sub["id"]
    runner.result.account_alias = sub["name"]

    for name, key, func, service, scope in AZURE_MODULES:
        runner.register(name, key, func, service=service, scope=scope)

    _finalize(runner, output, out_format, remediation_script)


def _finalize(runner, output, out_format, remediation_script):
    result = runner.run()

    paths = attack_paths.analyze(result)
    if paths:
        console.print(f"[bold red]Attack paths identified:[/] {len(paths)}")
        for p in paths[:3]:
            console.print(f"  [red]{escape(p.severity.upper())}[/] {escape(p.title)}")

    summary = exec_summary.generate(result, attack_paths=paths)
    compliance_data = compliance.analyze(result)

    console.print(
        f"[bold white]Compliance:[/] CIS {compliance_data['cis_failed']}/{compliance_data['cis_total']} failed, "
        f"NIST {compliance_data['nist_failed']}/{compliance_data['nist_total']} failed"
        + (" (coverage partial: controls with no finding are not passes)" if result.overall_score is None else "")
    )

    rem_path = None
    if remediation_script:
        rem_path = remediation.generate(result, output)

    if out_format in ("html", "all"):
        report_path = html.generate(result, output, attack_paths_list=paths, summary=summary,
                                    compliance_data=compliance_data, remediation_path=rem_path)
        console.print(f"\n[bold green]HTML report:[/] {escape(report_path)}")

    if out_format in ("json", "all"):
        json_path = json_export.generate(result, output, attack_paths_list=paths, summary=summary,
                                         compliance_data=compliance_data, remediation_path=rem_path)
        console.print(f"[bold green]JSON report:[/] {escape(json_path)}")

    if out_format in ("pdf", "all") and pdf_available():
        try:
            pdf_path = pdf.generate(result, output, attack_paths_list=paths, summary=summary,
                                    compliance_data=compliance_data, remediation_path=rem_path)
            console.print(f"[bold green]PDF report:[/] {escape(pdf_path)}")
        except (OSError, ImportError) as e:
            console.print(f"[bold red]PDF report failed:[/] {escape(str(e)[:160])}")
            console.print(f"[dim]{escape(PDF_INSTALL_HINT)}[/]")

    if rem_path:
        console.print(f"[bold green]Remediation script:[/] {escape(rem_path)} (commands commented out, mode 0644; review before running)")
    else:
        console.print("[dim]No remediation script written (pass --remediation-script to get one).[/]")


if __name__ == "__main__":
    main()
