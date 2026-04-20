from dataclasses import dataclass, field
from datetime import datetime


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
class AuditResult:
    """Top-level container for an entire cloud audit"""
    provider: str
    account_id: str = ""
    account_alias: str = ""
    regions: list = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    finished_at: str = ""
    findings: list[CloudFinding] = field(default_factory=list)
    services: list[ServiceSummary] = field(default_factory=list)
    total_resources: int = 0
    total_findings: int = 0
    overall_score: int = 100

    def add_finding(self, finding: CloudFinding):
        self.findings.append(finding)

    def finalize(self):
        self.finished_at = datetime.now().isoformat()
        self.total_findings = len(self.findings)

        severity_deductions = {"critical": 15, "high": 8, "medium": 3, "low": 1}
        total_deduct = 0
        for f in self.findings:
            total_deduct += severity_deductions.get(f.severity, 0)
        self.overall_score = max(0, 100 - total_deduct)

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
