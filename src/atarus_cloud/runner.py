from rich.console import Console
from rich.markup import escape
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from atarus_cloud.models import AuditResult, GLOBAL, describe_error

console = Console()

# Module scopes. A global module runs once against the account; a regional
# module runs once per selected region (for Azure, once per subscription).
SCOPE_GLOBAL = "global"
SCOPE_REGIONAL = "regional"


class ModuleResult:
    def __init__(self, success: bool, message: str = ""):
        self.success = success
        self.message = message


class CloudRunner:
    """Runs the registered modules and keeps the coverage table honest.

    `sessions` maps a region (or the Azure "subscription" label) to the session a
    regional module should use there. `global_session` is used by global modules.
    Every module that is skipped, crashes or reports failure is written to
    result.coverage as a not-run line, never dropped.
    """

    def __init__(self, provider: str, sessions: dict = None, global_session=None,
                 verbose: bool = False, skip: list = None, only: list = None):
        self.provider = provider
        self.sessions = dict(sessions or {})
        self.global_session = global_session
        self.verbose = verbose
        self.skip = [s.strip().lower() for s in (skip or [])]
        self.only = [s.strip().lower() for s in (only or [])]
        self.result = AuditResult(provider=provider)
        self.result.regions = list(self.sessions.keys())
        self.modules = []

    def register(self, name: str, key: str, func, service: str = "", scope: str = SCOPE_REGIONAL):
        self.modules.append({
            "name": name, "key": key, "func": func,
            "service": service or key.upper(), "scope": scope,
        })

    def _should_run(self, key: str) -> bool:
        if self.only:
            return key in self.only
        if self.skip:
            return key not in self.skip
        return True

    def _skip_reason(self, key: str) -> str:
        if self.only:
            return "not listed in --only"
        return "skipped with --skip"

    def _regions_for(self, module: dict) -> list:
        if module["scope"] == SCOPE_GLOBAL:
            return [GLOBAL]
        return list(self.sessions.keys())

    def _session_for(self, module: dict, region: str):
        if module["scope"] == SCOPE_GLOBAL:
            return self.global_session if self.global_session is not None else next(iter(self.sessions.values()), None)
        return self.sessions[region]

    def _run_one(self, module: dict, region: str):
        name = module["name"]
        key = module["key"]
        service = module["service"]
        label = name if region == GLOBAL else f"{name} [{region}]"
        findings_before = len(self.result.findings)
        coverage_before = len(self.result.coverage)

        try:
            module_result = module["func"](self.result, self._session_for(module, region), self.verbose)
            if module_result is None:
                module_result = ModuleResult(success=True, message="")
            if module_result.success:
                console.print(f"  [green]done[/] {escape(label)}: {escape(module_result.message)}")
            else:
                console.print(f"  [yellow]not run[/] {escape(label)}: {escape(module_result.message)}")
                self.result.not_run(key, service, region, "all checks", module_result.message)
        except Exception as e:
            console.print(f"  [red]fail[/] {escape(label)}: {escape(describe_error(e))}")
            self.result.not_run(key, service, region, "all checks", f"module crashed, {describe_error(e)}")

        # Findings added by a regional module belong to that region.
        if region != GLOBAL:
            for f in self.result.findings[findings_before:]:
                if not f.region:
                    f.region = region

        if self.verbose:
            for rec in self.result.coverage[coverage_before:]:
                if rec.status != "checked":
                    console.print(f"    [yellow]not run[/] {escape(rec.check)}: {escape(rec.detail)}")

    def run(self):
        console.print()

        active = [m for m in self.modules if self._should_run(m["key"])]
        skipped = [m for m in self.modules if not self._should_run(m["key"])]

        console.print(f"[bold green]Provider:[/] {escape(self.provider.upper())}")
        console.print(f"[bold white]Account:[/] {escape(str(self.result.account_id))}")
        if self.provider == "aws":
            console.print(f"[bold white]Regions:[/] {escape(', '.join(self.result.regions) or 'none')}")
            if self.result.regions_not_checked:
                names = ", ".join(r["region"] for r in self.result.regions_not_checked)
                console.print(f"[bold white]Regions not checked:[/] {escape(names)}")
        console.print(f"[bold white]Modules:[/] {len(active)} active, {len(skipped)} skipped")
        console.print()

        for m in skipped:
            for region in self._regions_for(m):
                self.result.not_run(m["key"], m["service"], region, "all checks", self._skip_reason(m["key"]))
        if skipped:
            console.print(f"  [dim]Skipped: {escape(', '.join(m['key'] for m in skipped))}[/]")
            console.print()

        for module in active:
            with Progress(
                SpinnerColumn(),
                TextColumn(f"[bold cyan]{escape(module['name'])}[/]"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task(module["name"], total=None)
                for region in self._regions_for(module):
                    self._run_one(module, region)
            console.print()

        self.result.finalize()
        self.print_summary()
        return self.result

    def print_summary(self):
        result = self.result
        crit = len([f for f in result.findings if f.severity == "critical"])
        high = len([f for f in result.findings if f.severity == "high"])
        med = len([f for f in result.findings if f.severity == "medium"])
        low = len([f for f in result.findings if f.severity == "low"])

        console.print("[bold white]Audit complete[/]")
        if result.overall_score is None:
            console.print(f"  Score: [yellow]{escape(result.score_label())}[/]")
        else:
            console.print(f"  Score: {result.overall_score}/100 (every check ran)")
        console.print(f"  Findings: {result.total_findings} total")
        if crit:
            console.print(f"  [bold red]Critical: {crit}[/]")
        if high:
            console.print(f"  [red]High: {high}[/]")
        if med:
            console.print(f"  [yellow]Medium: {med}[/]")
        if low:
            console.print(f"  [green]Low: {low}[/]")
        console.print()
        self.print_coverage()

    def print_coverage(self, max_not_run_lines: int = 40):
        result = self.result
        table = Table(title="Coverage")
        table.add_column("Service", style="bold")
        table.add_column("Region")
        table.add_column("Status")
        table.add_column("Detail")
        styles = {"checked": "green", "partial": "yellow", "not run": "red"}
        for row in result.coverage_rows():
            table.add_row(
                escape(row["service"]), escape(row["region"]),
                f"[{styles.get(row['status'], 'white')}]{row['status']}[/]",
                escape(row["detail"]),
            )
        console.print(table)

        not_run = result.not_run_records
        if not_run or result.regions_not_checked:
            console.print()
            console.print(f"[bold yellow]Checks not run ({result.checks_not_run}):[/]")
            for entry in result.regions_not_checked:
                console.print(f"  - all regional services / {escape(entry['region'])}: {escape(entry['reason'])}")
            for rec in not_run[:max_not_run_lines]:
                console.print(f"  - {escape(rec.service)} / {escape(rec.region)} / {escape(rec.check)}: {escape(rec.detail)}")
            if len(not_run) > max_not_run_lines:
                console.print(f"  ... and {len(not_run) - max_not_run_lines} more, listed in the report")
            console.print()
