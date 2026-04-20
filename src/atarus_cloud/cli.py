import click
from rich.console import Console
from rich.table import Table
from atarus_cloud.runner import CloudRunner
from atarus_cloud.providers.aws import auth as aws_auth
from atarus_cloud.providers.aws import iam, s3
from atarus_cloud.reports import html, json_export, pdf, remediation

console = Console()

VERSION = "0.1.0"

BANNER = f"""
   ╔═╗╔╦╗╔═╗╦═╗╦ ╦╔═╗  ╔═╗╦  ╔═╗╦ ╦╔╦╗
   ╠═╣ ║ ╠═╣╠╦╝║ ║╚═╗  ║  ║  ║ ║║ ║ ║║
   ╩ ╩ ╩ ╩ ╩╩╚═╚═╝╚═╝  ╚═╝╩═╝╚═╝╚═╝═╩╝
   Atarus Offensive Security | v{VERSION}
"""

AWS_MODULES = [
    ("IAM audit", "iam", iam.run),
    ("S3 audit", "s3", s3.run),
]


@click.command()
@click.option("-p", "--provider", default="aws", type=click.Choice(["aws"]), help="Cloud provider")
@click.option("--profile", default=None, help="AWS profile name")
@click.option("--region", default="us-west-1", help="AWS region")
@click.option("-o", "--output", default="./output", help="Output directory")
@click.option("--format", "out_format", default="html", type=click.Choice(["html", "json", "pdf", "all"]), help="Report format")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--skip", default="", help="Comma-separated modules to skip")
@click.option("--only", default="", help="Comma-separated modules to run exclusively")
@click.option("--list-modules", is_flag=True, help="List available modules and exit")
@click.version_option(version=VERSION, prog_name="atarus-cloud")
def main(provider, profile, region, output, out_format, verbose, skip, only, list_modules):
    """atarus-cloud: Cloud security misconfiguration scanner by Atarus Offensive Security"""

    if list_modules:
        table = Table(title="Available modules (AWS)")
        table.add_column("Key", style="bold cyan")
        table.add_column("Description")
        for name, key, _ in AWS_MODULES:
            table.add_row(key, name)
        console.print(table)
        return

    console.print(BANNER, style="bold red")

    if provider == "aws":
        console.print(f"[bold white]Authenticating to AWS...[/]")
        session, identity = aws_auth.get_session(profile=profile, region=region)
        account_id = identity["Account"]
        user_arn = identity["Arn"]
        console.print(f"[bold white]Account:[/] {account_id}")
        console.print(f"[bold white]Identity:[/] {user_arn}")
        console.print(f"[bold white]Region:[/] {region}")

        skip_list = [s.strip() for s in skip.split(",") if s.strip()] if skip else []
        only_list = [s.strip() for s in only.split(",") if s.strip()] if only else []

        runner = CloudRunner(
            provider="aws",
            session=session,
            regions=[region],
            verbose=verbose,
            skip=skip_list,
            only=only_list,
        )
        runner.result.account_id = account_id
        runner.result.account_alias = aws_auth.get_account_alias(session)

        for name, key, func in AWS_MODULES:
            runner.register(name, key, func)

        result = runner.run()

        if out_format in ("html", "all"):
            report_path = html.generate(result, output)
            console.print(f"\n[bold green]HTML report:[/] {report_path}")

        if out_format in ("json", "all"):
            json_path = json_export.generate(result, output)
            console.print(f"[bold green]JSON report:[/] {json_path}")

        if out_format in ("pdf", "all"):
            pdf_path = pdf.generate(result, output)
            console.print(f"[bold green]PDF report:[/] {pdf_path}")

        rem_path = remediation.generate(result, output)
        console.print(f"[bold green]Remediation script:[/] {rem_path}")


if __name__ == "__main__":
    main()
