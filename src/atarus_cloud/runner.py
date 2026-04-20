from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from atarus_cloud.models import AuditResult

console = Console()


class ModuleResult:
    def __init__(self, success: bool, message: str = ""):
        self.success = success
        self.message = message


class CloudRunner:
    def __init__(self, provider: str, session=None, regions: list = None,
                 verbose: bool = False, skip: list = None, only: list = None):
        self.provider = provider
        self.session = session
        self.regions = regions or []
        self.verbose = verbose
        self.skip = [s.strip().lower() for s in (skip or [])]
        self.only = [s.strip().lower() for s in (only or [])]
        self.result = AuditResult(provider=provider)
        self.modules = []

    def register(self, name: str, key: str, func):
        self.modules.append({"name": name, "key": key, "func": func})

    def _should_run(self, key: str) -> bool:
        if self.only:
            return key in self.only
        if self.skip:
            return key not in self.skip
        return True

    def run(self):
        console.print()

        active = [m for m in self.modules if self._should_run(m["key"])]
        skipped = len(self.modules) - len(active)

        console.print(f"[bold green]Provider:[/] {self.provider.upper()}")
        console.print(f"[bold white]Account:[/] {self.result.account_id}")
        console.print(f"[bold white]Modules:[/] {len(active)} active, {skipped} skipped")
        console.print()

        if skipped and self.verbose:
            skip_names = [m["key"] for m in self.modules if not self._should_run(m["key"])]
            console.print(f"  [dim]Skipped: {', '.join(skip_names)}[/]")
            console.print()

        for module in active:
            name = module["name"]
            func = module["func"]

            with Progress(
                SpinnerColumn(),
                TextColumn(f"[bold cyan]{name}[/]"),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            ) as progress:
                task = progress.add_task(name, total=None)

                try:
                    module_result = func(self.result, self.session, self.verbose)

                    if module_result.success:
                        console.print(f"  [green]done[/] {module_result.message}")
                    else:
                        console.print(f"  [yellow]warn[/] {module_result.message}")

                except Exception as e:
                    console.print(f"  [red]fail[/] {name}")
                    if self.verbose:
                        console.print(f"  [red]Error: {e}[/]")

            console.print()

        self.result.finalize()

        crit = len([f for f in self.result.findings if f.severity == "critical"])
        high = len([f for f in self.result.findings if f.severity == "high"])
        med = len([f for f in self.result.findings if f.severity == "medium"])
        low = len([f for f in self.result.findings if f.severity == "low"])

        console.print(f"[bold white]Audit complete[/]")
        console.print(f"  Score: {self.result.overall_score}/100")
        console.print(f"  Findings: {self.result.total_findings} total")
        if crit:
            console.print(f"  [bold red]Critical: {crit}[/]")
        if high:
            console.print(f"  [red]High: {high}[/]")
        if med:
            console.print(f"  [yellow]Medium: {med}[/]")
        if low:
            console.print(f"  [green]Low: {low}[/]")

        return self.result
