import click
from rich.console import Console
from rich.table import Table
from atarus_cloud.runner import CloudRunner
from atarus_cloud.providers.aws import auth as aws_auth
from atarus_cloud.providers.aws import iam, s3, ec2, cloudtrail, rds, vpc, lambda_fn, kms, secrets
from atarus_cloud.providers.azure import auth as az_auth
from atarus_cloud.providers.azure import identity as az_identity, storage as az_storage, network as az_network, compute as az_compute
from atarus_cloud.providers.azure import keyvault as az_keyvault, sql as az_sql, cosmosdb as az_cosmosdb
from atarus_cloud.analysis import attack_paths, exec_summary, compliance
from atarus_cloud.reports import html, json_export, pdf, remediation

console = Console()

VERSION = "0.9.0"

BANNER = f"""
   ╔═╗╔╦╗╔═╗╦═╗╦ ╦╔═╗  ╔═╗╦  ╔═╗╦ ╦╔╦╗
   ╠═╣ ║ ╠═╣╠╦╝║ ║╚═╗  ║  ║  ║ ║║ ║ ║║
   ╩ ╩ ╩ ╩ ╩╩╚═╚═╝╚═╝  ╚═╝╩═╝╚═╝╚═╝═╩╝
   Atarus Offensive Security | v{VERSION}
"""

AWS_MODULES = [
    ("IAM audit", "iam", iam.run),
    ("S3 audit", "s3", s3.run),
    ("EC2 audit", "ec2", ec2.run),
    ("CloudTrail audit", "cloudtrail", cloudtrail.run),
    ("RDS audit", "rds", rds.run),
    ("VPC audit", "vpc", vpc.run),
    ("Lambda audit", "lambda", lambda_fn.run),
    ("KMS audit", "kms", kms.run),
    ("Secrets Manager audit", "secrets", secrets.run),
]

AZURE_MODULES = [
    ("Identity audit", "identity", az_identity.run),
    ("Storage audit", "storage", az_storage.run),
    ("Network audit", "network", az_network.run),
    ("Compute audit", "compute", az_compute.run),
    ("Key Vault audit", "keyvault", az_keyvault.run),
    ("SQL audit", "sql", az_sql.run),
    ("Cosmos DB audit", "cosmosdb", az_cosmosdb.run),
]


@click.command()
@click.option("-p", "--provider", default="aws", type=click.Choice(["aws", "azure"]), help="Cloud provider")
@click.option("--profile", default=None, help="AWS profile name (AWS only)")
@click.option("--subscription", default=None, help="Azure subscription ID (Azure only)")
@click.option("--region", default="us-west-1", help="AWS region (AWS only)")
@click.option("-o", "--output", default="./output", help="Output directory")
@click.option("--format", "out_format", default="html", type=click.Choice(["html", "json", "pdf", "all"]), help="Report format")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--skip", default="", help="Comma-separated modules to skip")
@click.option("--only", default="", help="Comma-separated modules to run exclusively")
@click.option("--list-modules", is_flag=True, help="List available modules and exit")
@click.version_option(version=VERSION, prog_name="atarus-cloud")
def main(provider, profile, subscription, region, output, out_format, verbose, skip, only, list_modules):
    """atarus-cloud: Cloud security misconfiguration scanner by Atarus Offensive Security"""

    if list_modules:
        table = Table(title="Available modules")
        table.add_column("Provider", style="bold yellow")
        table.add_column("Key", style="bold cyan")
        table.add_column("Description")
        for name, key, _ in AWS_MODULES:
            table.add_row("aws", key, name)
        for name, key, _ in AZURE_MODULES:
            table.add_row("azure", key, name)
        console.print(table)
        return

    console.print(BANNER, style="bold red")

    skip_list = [s.strip() for s in skip.split(",") if s.strip()] if skip else []
    only_list = [s.strip() for s in only.split(",") if s.strip()] if only else []

    if provider == "aws":
        _run_aws(profile, region, skip_list, only_list, verbose, output, out_format)
    elif provider == "azure":
        _run_azure(subscription, skip_list, only_list, verbose, output, out_format)


def _run_aws(profile, region, skip_list, only_list, verbose, output, out_format):
    console.print(f"[bold white]Authenticating to AWS...[/]")
    session, identity = aws_auth.get_session(profile=profile, region=region)
    account_id = identity["Account"]
    user_arn = identity["Arn"]
    console.print(f"[bold white]Account:[/] {account_id}")
    console.print(f"[bold white]Identity:[/] {user_arn}")
    console.print(f"[bold white]Region:[/] {region}")

    runner = CloudRunner(
        provider="aws", session=session, regions=[region],
        verbose=verbose, skip=skip_list, only=only_list,
    )
    runner.result.account_id = account_id
    runner.result.account_alias = aws_auth.get_account_alias(session)

    for name, key, func in AWS_MODULES:
        runner.register(name, key, func)

    _finalize(runner, output, out_format)


def _run_azure(subscription_id, skip_list, only_list, verbose, output, out_format):
    console.print(f"[bold white]Authenticating to Azure...[/]")
    credential = az_auth.get_credential()

    if subscription_id:
        sub = az_auth.get_subscription_by_id(credential, subscription_id)
    else:
        sub = az_auth.get_default_subscription(credential)

    console.print(f"[bold white]Tenant:[/] {sub['tenant_id']}")
    console.print(f"[bold white]Subscription:[/] {sub['id']}")
    console.print(f"[bold white]Name:[/] {sub['name']}")

    azure_session = {
        "credential": credential,
        "subscription_id": sub["id"],
        "tenant_id": sub["tenant_id"],
    }

    runner = CloudRunner(
        provider="azure", session=azure_session,
        verbose=verbose, skip=skip_list, only=only_list,
    )
    runner.result.account_id = sub["id"]
    runner.result.account_alias = sub["name"]

    for name, key, func in AZURE_MODULES:
        runner.register(name, key, func)

    _finalize(runner, output, out_format)


def _finalize(runner, output, out_format):
    result = runner.run()

    paths = attack_paths.analyze(result)
    if paths:
        console.print(f"[bold red]Attack paths identified:[/] {len(paths)}")
        for p in paths[:3]:
            console.print(f"  [red]{p.severity.upper()}[/] {p.title}")

    summary = exec_summary.generate(result, attack_paths=paths)
    compliance_data = compliance.analyze(result)

    console.print(f"[bold white]Compliance:[/] CIS {compliance_data['cis_failed']}/{compliance_data['cis_total']} failed, NIST {compliance_data['nist_failed']}/{compliance_data['nist_total']} failed")

    if out_format in ("html", "all"):
        report_path = html.generate(result, output, attack_paths_list=paths, summary=summary, compliance_data=compliance_data)
        console.print(f"\n[bold green]HTML report:[/] {report_path}")

    if out_format in ("json", "all"):
        json_path = json_export.generate(result, output, attack_paths_list=paths, summary=summary, compliance_data=compliance_data)
        console.print(f"[bold green]JSON report:[/] {json_path}")

    if out_format in ("pdf", "all"):
        pdf_path = pdf.generate(result, output, attack_paths_list=paths, summary=summary, compliance_data=compliance_data)
        console.print(f"[bold green]PDF report:[/] {pdf_path}")

    rem_path = remediation.generate(result, output)
    console.print(f"[bold green]Remediation script:[/] {rem_path}")


if __name__ == "__main__":
    main()
