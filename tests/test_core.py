"""Offline unit tests for atarus-cloud. Standard library only; cloud APIs are faked."""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from atarus_cloud.models import AuditResult, CloudFinding
from atarus_cloud.providers.aws import iam, ec2
from atarus_cloud.analysis import attack_paths, exec_summary, compliance
from atarus_cloud.reports import html, json_export, remediation


class NoSuchEntity(Exception):
    pass


def fake_iam():
    client = mock.MagicMock()
    client.exceptions.NoSuchEntityException = NoSuchEntity
    old = datetime.now(timezone.utc) - timedelta(days=200)
    client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
    client.list_users.return_value = {"Users": [{"UserName": "alice", "PasswordLastUsed": old}]}
    client.list_mfa_devices.return_value = {"MFADevices": []}
    client.get_login_profile.return_value = {}
    client.list_access_keys.return_value = {"AccessKeyMetadata": [
        {"AccessKeyId": "AKIAEXAMPLEEXAMPLE00", "CreateDate": old, "Status": "Inactive"}]}
    client.get_account_password_policy.side_effect = NoSuchEntity()
    client.list_attached_user_policies.return_value = {"AttachedPolicies": [
        {"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}
    return client


def session_with(**clients):
    s = mock.MagicMock()
    s.client.side_effect = lambda name, **kw: clients[name]
    return s


class ModelTests(unittest.TestCase):
    def test_finalize_scores_and_groups(self):
        r = AuditResult(provider="aws")
        for sev in ("critical", "high", "medium", "low"):
            r.add_finding(CloudFinding(service="IAM", resource_id="x", resource_name="x", severity=sev,
                                       observation="o", risk="r", recommendation="c"))
        r.finalize()
        self.assertEqual(r.overall_score, 100 - (15 + 8 + 3 + 1))
        self.assertEqual(r.services[0].findings_count, 4)


class AwsModuleTests(unittest.TestCase):
    def test_iam_findings(self):
        r = AuditResult(provider="aws")
        res = iam.run(r, session_with(iam=fake_iam()), False)
        self.assertTrue(res.success)
        titles = [f.observation for f in r.findings]
        self.assertTrue(any("root account does not have MFA" in t for t in titles))
        self.assertTrue(any("console access but no MFA" in t for t in titles))
        self.assertTrue(any("No account password policy" in t for t in titles))
        self.assertTrue(any("AdministratorAccess" in t for t in titles))
        self.assertTrue(any("Inactive access key" in t for t in titles))
        self.assertTrue(any("not logged in for" in t for t in titles))

    def test_ec2_open_ssh(self):
        client = mock.MagicMock()
        client.describe_security_groups.return_value = {"SecurityGroups": [{
            "GroupId": "sg-1", "GroupName": "open-ssh",
            "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}
        client.describe_instances.return_value = {"Reservations": []}
        client.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": True}
        r = AuditResult(provider="aws")
        ec2.run(r, session_with(ec2=client), False)
        ssh = [f for f in r.findings if "SSH" in f.observation]
        self.assertEqual(len(ssh), 1)
        self.assertEqual(ssh[0].severity, "critical")


class AnalysisAndReportTests(unittest.TestCase):
    def _result(self):
        r = AuditResult(provider="aws", account_id="123456789012")
        iam.run(r, session_with(iam=fake_iam()), False)
        r.finalize()
        return r

    def test_analysis_and_reports(self):
        r = self._result()
        paths = attack_paths.analyze(r)
        summary = exec_summary.generate(r, attack_paths=paths)
        comp = compliance.analyze(r)
        self.assertIn("cis_failed", comp)
        self.assertTrue(summary)
        with tempfile.TemporaryDirectory() as d:
            h = html.generate(r, d, attack_paths_list=paths, summary=summary, compliance_data=comp)
            with open(h) as f:
                self.assertIn("123456789012", f.read())
            j = json_export.generate(r, d, attack_paths_list=paths, summary=summary, compliance_data=comp)
            with open(j) as f:
                self.assertTrue(json.load(f))
            sh = remediation.generate(r, d)
            with open(sh) as f:
                script = f.read()
            self.assertTrue(script.startswith("#!/bin/bash"))
            self.assertIn("aws iam delete-access-key", script)
            self.assertTrue(os.access(sh, os.X_OK))


class CliTests(unittest.TestCase):
    def test_cli_imports_and_lists_modules(self):
        # Importing cli pulls in every AWS and Azure module; this fails if a
        # declared dependency is missing (the v1.0.0 install bug).
        from click.testing import CliRunner
        from atarus_cloud import cli
        out = CliRunner().invoke(cli.main, ["--list-modules"])
        self.assertEqual(out.exit_code, 0, out.output)
        for key in ("iam", "s3", "cosmosdb", "sql", "keyvault"):
            self.assertIn(key, out.output)

    def test_template_ships_inside_package(self):
        import atarus_cloud
        pkg = os.path.dirname(atarus_cloud.__file__)
        self.assertTrue(os.path.exists(os.path.join(pkg, "templates", "cloud_report.html")))


if __name__ == "__main__":
    unittest.main()
