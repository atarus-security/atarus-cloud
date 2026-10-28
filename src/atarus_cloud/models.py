import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# Coverage statuses. "checked" means the check ran to completion against every
# resource it could see. "not_run" means it did not: the API call failed, the
# module was skipped, the region was not selected, or the SDK is missing.
CHECKED = "checked"
NOT_RUN = "not_run"

# Scope labels used in the "region" column of the coverage table.
GLOBAL = "global"            # AWS services without a region (IAM, S3 listing)
SUBSCRIPTION = "subscription"  # Azure: every module lists subscription-wide


def describe_error(exc: BaseException, limit: int = 200) -> str:
    """One line naming the exception type and its message, for a not-run reason."""
    text = str(exc).strip() or "no message"
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:limit] + "..."
    return f"{type(exc).__name__}: {text}"


def file_stem(value: str) -> str:
    """Reduce an account or subscription id to characters safe in a file name."""
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "")
    return stem.strip("._") or "account"


@dataclass
class CloudFinding:
    """A single security finding with observation, risk, and recommendation"""
    service: str
    resource_id: str
    resource_name: str
    severity: str
    observation: str
    risk: str
    recommendation: str
    remediation_cmd: str = ""
    remediation_effort: str = ""
    provider: str = "aws"
    region: str = ""
    compliance: list = field(default_factory=list)


@dataclass
class ServiceSummary:
    """Summary of findings for one service"""
    name: str
    resources_checked: int = 0
    findings_count: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


@dataclass
class CheckRecord:
    """One row of the coverage table: did this check run, where, and if not, why."""
    module: str
    service: str
    region: str
    check: str
    status: str
    detail: str = ""


class CoverageRecorder:
    """Records checks for one module in one region. Handed to module code so it
    does not have to repeat the module, service and region on every line."""

    def __init__(self, result: "AuditResult", module: str, service: str, region: str):
        self.result = result
        self.module = module
        self.service = service
        self.region = region

    def checked(self, check: str, detail: str = ""):
        self.result.coverage.append(CheckRecord(
            module=self.module, service=self.service, region=self.region,
            check=check, status=CHECKED, detail=detail,
        ))

    def not_run(self, check: str, reason):
        if isinstance(reason, BaseException):
            reason = describe_error(reason)
        self.result.coverage.append(CheckRecord(
            module=self.module, service=self.service, region=self.region,
            check=check, status=NOT_RUN, detail=str(reason),
        ))


@dataclass
class AuditResult:
    """Top-level container for an entire cloud audit"""
    provider: str
    account_id: str = ""
    account_alias: str = ""
    regions: list = field(default_factory=list)
    regions_not_checked: list = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    finished_at: str = ""
    findings: list[CloudFinding] = field(default_factory=list)
    services: list[ServiceSummary] = field(default_factory=list)
    coverage: list[CheckRecord] = field(default_factory=list)
    coverage_status: str = "complete"
    checks_total: int = 0
    checks_not_run: int = 0
    total_resources: int = 0
    total_findings: int = 0
    # None when coverage is partial: a score over an incomplete set of checks
    # would read as a clean result for the checks that never ran.
    overall_score: Optional[int] = None

    def add_finding(self, finding: CloudFinding):
        self.findings.append(finding)

    def recorder(self, module: str, service: str, region: str) -> CoverageRecorder:
        return CoverageRecorder(self, module, service, region)

    def not_run(self, module: str, service: str, region: str, check: str, reason):
        self.recorder(module, service, region).not_run(check, reason)

    @property
    def not_run_records(self) -> list:
        return [c for c in self.coverage if c.status == NOT_RUN]

    @property
    def coverage_complete(self) -> bool:
        return not self.not_run_records and not self.regions_not_checked

    def score_label(self) -> str:
        if self.overall_score is None:
            return f"partial coverage, no score ({self.checks_not_run} of {self.checks_total} checks did not run)"
        return f"{self.overall_score}/100"

    def finalize(self):
        self.finished_at = datetime.now().isoformat()
        self.total_findings = len(self.findings)
        self.checks_total = len(self.coverage) + len(self.regions_not_checked)
        self.checks_not_run = len(self.not_run_records) + len(self.regions_not_checked)
        self.coverage_status = "complete" if self.coverage_complete else "partial"

        if self.coverage_complete:
            severity_deductions = {"critical": 15, "high": 8, "medium": 3, "low": 1}
            total_deduct = 0
            for f in self.findings:
                total_deduct += severity_deductions.get(f.severity, 0)
            self.overall_score = max(0, 100 - total_deduct)
        else:
            self.overall_score = None

        service_map = {}
        for f in self.findings:
            if f.service not in service_map:
                service_map[f.service] = ServiceSummary(name=f.service)
            s = service_map[f.service]
            s.findings_count += 1
            if f.severity == "critical":
                s.critical += 1
            elif f.severity == "high":
                s.high += 1
            elif f.severity == "medium":
                s.medium += 1
            elif f.severity == "low":
                s.low += 1
        self.services = sorted(service_map.values(), key=lambda s: s.findings_count, reverse=True)

    def coverage_rows(self) -> list:
        """Aggregate the coverage records per service and region for the console table.
        Returns dicts with service, region, status ('checked', 'partial', 'not run'),
        checked, total and a short detail."""
        groups = {}
        order = []
        for rec in self.coverage:
            key = (rec.service, rec.region)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(rec)

        rows = []
        for key in order:
            recs = groups[key]
            total = len(recs)
            missing = [r for r in recs if r.status == NOT_RUN]
            if not missing:
                status = "checked"
                detail = f"{total} check{'s' if total != 1 else ''}"
            elif len(missing) == total:
                status = "not run"
                detail = missing[0].detail
            else:
                status = "partial"
                detail = f"{len(missing)} of {total} checks did not run"
            rows.append({
                "service": key[0], "region": key[1], "status": status,
                "checked": total - len(missing), "total": total, "detail": detail,
            })
        for entry in self.regions_not_checked:
            rows.append({
                "service": "all regional services", "region": entry["region"],
                "status": "not run", "checked": 0, "total": 0, "detail": entry["reason"],
            })
        return rows
