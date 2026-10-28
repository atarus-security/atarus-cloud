"""Tests for the coverage table, the withheld score, region selection, the
opt-in remediation script and the optional extras.

Standard library plus click's CliRunner. Every SDK client is a MagicMock and
the socket layer is guarded, so no test can reach a cloud API by accident.
"""
import contextlib
import io
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from botocore.exceptions import ClientError
from click.testing import CliRunner
from rich.console import Console

import atarus_cloud
from atarus_cloud import cli, runner as runner_module
from atarus_cloud.models import AuditResult, CloudFinding, GLOBAL, SUBSCRIPTION, describe_error, file_stem
from atarus_cloud.providers.aws import auth as aws_auth, iam, s3, ec2, cloudtrail, kms
from atarus_cloud.providers.azure import identity as az_identity, storage as az_storage, sql as az_sql
from atarus_cloud.analysis import exec_summary, compliance
from atarus_cloud.reports import html, json_export, remediation
from atarus_cloud.runner import CloudRunner, ModuleResult, SCOPE_GLOBAL, SCOPE_REGIONAL


def _network_refused(*args, **kwargs):
    raise AssertionError("a real network call was attempted")


class _NetworkGuard:
    """Patches the socket layer so any unmocked connection fails loudly."""

    def __init__(self):
        self._patches = [
            mock.patch.object(socket.socket, "connect", side_effect=_network_refused),
            mock.patch.object(socket.socket, "connect_ex", side_effect=_network_refused),
            mock.patch.object(socket, "create_connection", side_effect=_network_refused),
            mock.patch.object(socket, "getaddrinfo", side_effect=_network_refused),
        ]

    def __enter__(self):
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()
        return False


@contextlib.contextmanager
def _quiet_console():
    sink = Console(file=io.StringIO(), width=120)
    with mock.patch.object(runner_module, "console", sink), mock.patch.object(cli, "console", sink):
        yield sink


def aws_error(code, operation="Op"):
    return ClientError({"Error": {"Code": code, "Message": f"{code} for test"}}, operation)


class NoSuchEntity(Exception):
    pass


class ResourceNotFound(Exception):
    pass


class UnsupportedOperation(Exception):
    pass


def fake_client():
    """A client whose every call returns an empty, iterable MagicMock and whose
    exception classes are real exceptions."""
    client = mock.MagicMock()
    client.exceptions.NoSuchEntityException = NoSuchEntity
    client.exceptions.ResourceNotFoundException = ResourceNotFound
    client.exceptions.UnsupportedOperationException = UnsupportedOperation
    client.exceptions.ClientError = ClientError
    return client


def fake_session(region="us-west-1", **clients):
    """A boto3-like session: session.client(name) returns the named fake or a fresh one."""
    s = mock.MagicMock()
    s.region_name = region
    store = dict(clients)

    def client(name, **kw):
        if name not in store:
            store[name] = fake_client()
        return store[name]

    s.client.side_effect = client
    s.clients = store
    return s


def quiet_iam():
    """An IAM client with one user and nothing wrong, so every IAM check passes cleanly."""
    c = fake_client()
    c.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
    c.list_users.return_value = {"Users": [{"UserName": "alice"}]}
    c.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "x"}]}
    c.list_access_keys.return_value = {"AccessKeyMetadata": []}
    c.get_account_password_policy.return_value = {"PasswordPolicy": {
        "MinimumPasswordLength": 16, "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True,
        "RequireNumbers": True, "RequireSymbols": True}}
    c.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    return c


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ModelTests(unittest.TestCase):
    def _finding(self, sev="high", service="IAM"):
        return CloudFinding(service=service, resource_id="x", resource_name="x", severity=sev,
                            observation="o", risk="r", recommendation="c")

    def test_score_only_when_every_check_ran(self):
        r = AuditResult(provider="aws")
        cov = r.recorder("iam", "IAM", GLOBAL)
        cov.checked("root account MFA")
        r.add_finding(self._finding("high"))
        r.finalize()
        self.assertEqual(r.coverage_status, "complete")
        self.assertEqual(r.overall_score, 92)
        self.assertEqual(r.score_label(), "92/100")

    def test_one_not_run_line_withholds_the_score(self):
        r = AuditResult(provider="aws")
        cov = r.recorder("iam", "IAM", GLOBAL)
        cov.checked("root account MFA")
        cov.not_run("console users without MFA", aws_error("AccessDenied", "ListUsers"))
        r.finalize()
        self.assertEqual(r.coverage_status, "partial")
        self.assertIsNone(r.overall_score)
        self.assertEqual(r.checks_total, 2)
        self.assertEqual(r.checks_not_run, 1)
        self.assertIn("1 of 2 checks did not run", r.score_label())
        self.assertIn("AccessDenied", r.not_run_records[0].detail)
        self.assertTrue(r.not_run_records[0].detail.startswith("ClientError:"))

    def test_unchecked_region_withholds_the_score(self):
        r = AuditResult(provider="aws")
        r.recorder("ec2", "EC2", "us-west-1").checked("security groups")
        r.regions_not_checked = [{"region": "eu-west-1", "reason": "not in the --region list"}]
        r.finalize()
        self.assertIsNone(r.overall_score)
        self.assertEqual(r.checks_not_run, 1)
        rows = r.coverage_rows()
        self.assertEqual(rows[-1]["region"], "eu-west-1")
        self.assertEqual(rows[-1]["status"], "not run")

    def test_coverage_rows_aggregate_per_service_and_region(self):
        r = AuditResult(provider="aws")
        a = r.recorder("ec2", "EC2", "us-west-1")
        a.checked("security groups")
        a.checked("public instances")
        b = r.recorder("ec2", "EC2", "eu-west-1")
        b.checked("security groups")
        b.not_run("public instances", "AccessDenied")
        c = r.recorder("rds", "RDS", "eu-west-1")
        c.not_run("all checks", "Cannot describe RDS instances")
        r.finalize()
        rows = {(row["service"], row["region"]): row for row in r.coverage_rows()}
        self.assertEqual(rows[("EC2", "us-west-1")]["status"], "checked")
        self.assertEqual(rows[("EC2", "eu-west-1")]["status"], "partial")
        self.assertIn("1 of 2", rows[("EC2", "eu-west-1")]["detail"])
        self.assertEqual(rows[("RDS", "eu-west-1")]["status"], "not run")
        self.assertIn("Cannot describe", rows[("RDS", "eu-west-1")]["detail"])

    def test_helpers(self):
        self.assertEqual(file_stem("123456789012"), "123456789012")
        self.assertEqual(file_stem("../etc/passwd"), "etc_passwd")
        self.assertEqual(file_stem(""), "account")
        text = describe_error(ValueError("a\nb" + "x" * 300))
        self.assertTrue(text.startswith("ValueError: a b"))
        self.assertLess(len(text), 230)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class RunnerTests(unittest.TestCase):
    def _runner(self, regions=("us-west-1", "eu-west-1"), **kw):
        sessions = {r: fake_session(r) for r in regions}
        return CloudRunner(provider="aws", sessions=sessions, global_session=fake_session("us-east-1"), **kw)

    def test_regional_module_runs_per_region_and_tags_findings(self):
        seen = []

        def regional(result, session, verbose):
            seen.append(session.region_name)
            result.recorder("ec2", "EC2", session.region_name).checked("security groups")
            result.add_finding(CloudFinding(service="EC2", resource_id="sg", resource_name="sg", severity="low",
                                            observation="o", risk="r", recommendation="c"))
            return ModuleResult(True, "ok")

        def global_mod(result, session, verbose):
            seen.append("global:" + session.region_name)
            result.recorder("iam", "IAM", GLOBAL).checked("root")
            return ModuleResult(True, "ok")

        runner = self._runner()
        runner.register("EC2 audit", "ec2", regional, service="EC2", scope=SCOPE_REGIONAL)
        runner.register("IAM audit", "iam", global_mod, service="IAM", scope=SCOPE_GLOBAL)
        with _quiet_console():
            result = runner.run()
        self.assertEqual(seen, ["us-west-1", "eu-west-1", "global:us-east-1"])
        self.assertEqual(sorted(f.region for f in result.findings), ["eu-west-1", "us-west-1"])
        self.assertEqual(result.coverage_status, "complete")
        self.assertEqual(result.overall_score, 98)

    def test_skipped_crashed_and_failed_modules_become_not_run_lines(self):
        def crashes(result, session, verbose):
            raise RuntimeError("boom")

        def fails(result, session, verbose):
            return ModuleResult(False, "Cannot list buckets: AccessDenied")

        def fine(result, session, verbose):
            result.recorder("vpc", "VPC", session.region_name).checked("flow logs")
            return ModuleResult(True, "")

        runner = self._runner(regions=("us-west-1",), skip=["kms"])
        runner.register("EC2 audit", "ec2", crashes, service="EC2")
        runner.register("S3 audit", "s3", fails, service="S3", scope=SCOPE_GLOBAL)
        runner.register("VPC audit", "vpc", fine, service="VPC")
        runner.register("KMS audit", "kms", fine, service="KMS")
        with _quiet_console():
            result = runner.run()
        reasons = {(c.service, c.region): c.detail for c in result.not_run_records}
        self.assertIn("module crashed, RuntimeError: boom", reasons[("EC2", "us-west-1")])
        self.assertEqual(reasons[("S3", GLOBAL)], "Cannot list buckets: AccessDenied")
        self.assertEqual(reasons[("KMS", "us-west-1")], "skipped with --skip")
        self.assertIsNone(result.overall_score)
        self.assertEqual(result.coverage_status, "partial")

    def test_only_records_the_rest_as_not_run(self):
        def fine(result, session, verbose):
            result.recorder("vpc", "VPC", session.region_name).checked("flow logs")
            return ModuleResult(True, "")

        runner = self._runner(regions=("us-west-1",), only=["vpc"])
        runner.register("VPC audit", "vpc", fine, service="VPC")
        runner.register("KMS audit", "kms", fine, service="KMS")
        with _quiet_console():
            result = runner.run()
        kms_lines = [c for c in result.not_run_records if c.service == "KMS"]
        self.assertEqual(len(kms_lines), 1)
        self.assertEqual(kms_lines[0].detail, "not listed in --only")

    def test_console_output_escapes_rich_markup_in_resource_names(self):
        def fine(result, session, verbose):
            result.recorder("vpc", "VPC", session.region_name).not_run("flow logs", "[bold red]injected[/]")
            return ModuleResult(True, "[blink]x[/]")

        runner = self._runner(regions=("us-west-1",), verbose=True)
        runner.register("VPC audit", "vpc", fine, service="VPC")
        with _quiet_console() as sink:
            runner.run()
        text = sink.file.getvalue()
        self.assertIn("[bold red]injected[/]", text)
        self.assertIn("[blink]x[/]", text)


# ---------------------------------------------------------------------------
# Modules: every swallowed exception is a not-run line, never a silent pass
# ---------------------------------------------------------------------------

class AwsModuleCoverageTests(unittest.TestCase):
    def test_iam_access_denied_is_recorded_not_swallowed(self):
        client = quiet_iam()
        client.get_account_summary.side_effect = aws_error("AccessDenied", "GetAccountSummary")
        r = AuditResult(provider="aws")
        res = iam.run(r, fake_session(iam=client), False)
        self.assertTrue(res.success)
        self.assertEqual(r.findings, [])
        not_run = {c.check: c.detail for c in r.not_run_records}
        self.assertIn("root account MFA", not_run)
        self.assertIn("AccessDenied", not_run["root account MFA"])
        checked = {c.check for c in r.coverage if c.status == "checked"}
        self.assertIn("console users without MFA", checked)
        self.assertIn("account password policy", checked)
        r.finalize()
        self.assertIsNone(r.overall_score)

    def test_iam_clean_account_scores_100_only_with_full_coverage(self):
        r = AuditResult(provider="aws")
        iam.run(r, fake_session(iam=quiet_iam()), False)
        r.finalize()
        self.assertEqual(r.findings, [])
        self.assertEqual(len(r.coverage), 6)
        self.assertEqual(r.overall_score, 100)

    def test_iam_cannot_list_users_is_a_module_failure(self):
        client = quiet_iam()
        client.list_users.side_effect = aws_error("AccessDenied", "ListUsers")
        res = iam.run(AuditResult(provider="aws"), fake_session(iam=client), False)
        self.assertFalse(res.success)
        self.assertIn("AccessDenied", res.message)

    def test_s3_unexpected_error_codes_are_not_run_lines(self):
        client = fake_client()
        client.list_buckets.return_value = {"Buckets": [{"Name": "open"}, {"Name": "locked"}]}

        def pab(Bucket):
            if Bucket == "open":
                raise aws_error("NoSuchPublicAccessBlockConfiguration", "GetPublicAccessBlock")
            raise aws_error("AccessDenied", "GetPublicAccessBlock")

        client.get_public_access_block.side_effect = pab
        client.get_bucket_encryption.side_effect = aws_error("AccessDenied", "GetBucketEncryption")
        client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        client.get_bucket_logging.return_value = {"LoggingEnabled": {}}
        r = AuditResult(provider="aws")
        s3.run(r, fake_session(s3=client), False)
        observations = [f.observation for f in r.findings]
        self.assertTrue(any("'open' has no public access block" in o for o in observations))
        self.assertFalse(any("'locked'" in o for o in observations))
        not_run = {c.check: c.detail for c in r.not_run_records}
        self.assertIn("public access block (locked)", not_run)
        self.assertIn("default encryption (open)", not_run)
        self.assertIn("default encryption (locked)", not_run)
        checked = {c.check: c.detail for c in r.coverage if c.status == "checked"}
        self.assertEqual(checked["versioning"], "2 buckets")
        self.assertIn("1 of 2 buckets", checked["public access block"])

    def test_ec2_errors_per_check(self):
        client = fake_client()
        client.describe_security_groups.side_effect = aws_error("UnauthorizedOperation", "DescribeSecurityGroups")
        client.describe_instances.return_value = {"Reservations": []}
        client.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": False}
        r = AuditResult(provider="aws")
        ec2.run(r, fake_session("eu-west-1", ec2=client), False)
        not_run = [c for c in r.not_run_records]
        self.assertEqual(len(not_run), 1)
        self.assertEqual(not_run[0].check, "security groups open to the internet")
        self.assertEqual(not_run[0].region, "eu-west-1")
        self.assertTrue(any("EBS encryption by default is not enabled" in f.observation for f in r.findings))

    def test_cloudtrail_shadow_trails_are_checked_in_their_home_region_only(self):
        trail = {"Name": "org", "TrailARN": "arn:aws:cloudtrail:us-east-1:1:trail/org", "HomeRegion": "us-east-1",
                 "IsMultiRegionTrail": True, "LogFileValidationEnabled": False}
        home = fake_client()
        home.describe_trails.return_value = {"trailList": [trail]}
        home.get_trail_status.return_value = {"IsLogging": True}
        shadow = fake_client()
        shadow.describe_trails.return_value = {"trailList": [trail]}
        empty = fake_client()
        empty.describe_trails.return_value = {"trailList": []}

        r = AuditResult(provider="aws")
        cloudtrail.run(r, fake_session("us-east-1", cloudtrail=home), False)
        cloudtrail.run(r, fake_session("eu-west-1", cloudtrail=shadow), False)
        cloudtrail.run(r, fake_session("ap-south-1", cloudtrail=empty), False)

        validation = [f for f in r.findings if "log file validation" in f.observation]
        self.assertEqual(len(validation), 1)
        shadow.get_trail_status.assert_not_called()
        uncovered = [f for f in r.findings if "No CloudTrail trail covers region" in f.observation]
        self.assertEqual(len(uncovered), 1)
        self.assertIn("ap-south-1", uncovered[0].observation)
        self.assertEqual({c.region for c in r.coverage}, {"us-east-1", "eu-west-1", "ap-south-1"})
        self.assertEqual(r.not_run_records, [])

    def test_kms_describe_failure_is_a_not_run_line(self):
        client = fake_client()
        client.get_paginator.return_value.paginate.return_value = [{"Keys": [{"KeyId": "k1"}, {"KeyId": "k2"}]}]

        def describe(KeyId):
            if KeyId == "k2":
                raise aws_error("AccessDenied", "DescribeKey")
            return {"KeyMetadata": {"KeyId": "k1", "Arn": "arn:k1", "KeyManager": "CUSTOMER", "KeyState": "Enabled"}}

        client.describe_key.side_effect = describe
        client.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
        client.get_key_policy.return_value = {"Policy": json.dumps({"Statement": []})}
        r = AuditResult(provider="aws")
        kms.run(r, fake_session(kms=client), False)
        self.assertEqual([c.check for c in r.not_run_records], ["describe key (k2)"])
        inventory = [c for c in r.coverage if c.check == "key inventory"][0]
        self.assertIn("1 of 2", inventory.detail)


class AzureModuleCoverageTests(unittest.TestCase):
    def _session(self):
        return {"credential": mock.MagicMock(), "subscription_id": "sub-1", "tenant_id": "t"}

    def test_identity_without_role_definitions_is_not_a_silent_pass(self):
        client = mock.MagicMock()
        client.role_assignments.list_for_subscription.return_value = [mock.MagicMock()]
        client.role_definitions.list.side_effect = RuntimeError("Forbidden")
        with mock.patch.object(az_identity, "_client", return_value=client):
            r = AuditResult(provider="azure")
            res = az_identity.run(r, self._session(), False)
        self.assertTrue(res.success)
        self.assertEqual(len(r.not_run_records), 3)
        self.assertTrue(all("role definitions could not be listed" in c.detail for c in r.not_run_records))
        self.assertTrue(all(c.region == SUBSCRIPTION for c in r.coverage))

    def test_storage_container_listing_error_is_recorded(self):
        acct = mock.MagicMock()
        acct.name = "acct1"
        acct.id = "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/acct1"
        acct.enable_https_traffic_only = True
        acct.minimum_tls_version = "TLS1_2"
        acct.public_network_access = "Disabled"
        acct.allow_blob_public_access = False
        acct.encryption = None
        client = mock.MagicMock()
        client.storage_accounts.list.return_value = [acct]
        client.blob_containers.list.side_effect = RuntimeError("Forbidden")
        with mock.patch.object(az_storage, "_client", return_value=client):
            r = AuditResult(provider="azure")
            az_storage.run(r, self._session(), False)
        self.assertEqual(r.findings, [])
        self.assertEqual([c.check for c in r.not_run_records], ["public blob containers (acct1)"])
        client.blob_containers.list.assert_called_once_with("rg1", "acct1")

    def test_missing_sdk_is_a_clear_module_failure(self):
        with mock.patch.object(az_sql, "_client", side_effect=ImportError("No module named 'azure.mgmt.sql'")):
            res = az_sql.run(AuditResult(provider="azure"), self._session(), False)
        self.assertFalse(res.success)
        self.assertIn("pip install 'atarus-cloud[azure]'", res.message)


# ---------------------------------------------------------------------------
# Remediation script and command quoting
# ---------------------------------------------------------------------------

class RemediationScriptTests(unittest.TestCase):
    def _result_with_hostile_names(self):
        client = quiet_iam()
        old = datetime.now(timezone.utc) - timedelta(days=200)
        client.list_users.return_value = {"Users": [{"UserName": "evil$(id); rm -rf /"}]}
        client.list_access_keys.return_value = {"AccessKeyMetadata": [
            {"AccessKeyId": "AKIAEXAMPLEEXAMPLE00", "CreateDate": old, "Status": "Active"}]}
        r = AuditResult(provider="aws", account_id="123456789012")
        iam.run(r, fake_session(iam=client), False)

        s3c = fake_client()
        s3c.list_buckets.return_value = {"Buckets": [{"Name": "my bucket\necho pwned"}]}
        s3c.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
        s3c.get_bucket_encryption.return_value = {}
        s3c.get_bucket_versioning.return_value = {"Status": "Enabled"}
        s3c.get_bucket_logging.return_value = {"LoggingEnabled": {}}
        s3.run(r, fake_session(s3=s3c), False)
        r.finalize()
        return r

    def test_values_are_shell_quoted_in_commands(self):
        r = self._result_with_hostile_names()
        cmds = "\n".join(f.remediation_cmd for f in r.findings)
        self.assertIn("--user-name 'evil$(id); rm -rf /'", cmds)
        self.assertNotIn("--user-name evil$(id)", cmds)
        self.assertIn("--bucket 'my bucket", cmds)

    def test_script_is_commented_out_quoted_and_not_executable(self):
        r = self._result_with_hostile_names()
        with tempfile.TemporaryDirectory() as d:
            path = remediation.generate(r, d)
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o644)
            self.assertFalse(os.access(path, os.X_OK))
            with open(path) as f:
                lines = f.read().split("\n")
        self.assertEqual(lines[0], "#!/bin/bash")
        self.assertTrue(any("REVIEW BEFORE RUNNING" in line for line in lines[:8]))
        live = [line for line in lines if line.strip() and not line.startswith("#")]
        self.assertEqual(live, ["set -euo pipefail"])
        joined = "\n".join(lines)
        self.assertIn("# aws iam delete-access-key --user-name 'evil$(id); rm -rf /'", joined)
        # A newline inside a bucket name cannot start a new, uncommented line.
        self.assertNotIn("\necho pwned", joined)
        self.assertIn("commands listed, all commented out", lines[-2])

    def test_script_file_name_is_sanitised(self):
        r = AuditResult(provider="aws", account_id="../../x")
        r.finalize()
        with tempfile.TemporaryDirectory() as d:
            path = remediation.generate(r, d)
            self.assertEqual(os.path.dirname(path), d)
            self.assertEqual(os.path.basename(path), "remediation-x.sh")


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class ReportTests(unittest.TestCase):
    def _partial(self):
        r = AuditResult(provider="aws", account_id="123456789012")
        client = quiet_iam()
        client.get_account_summary.side_effect = aws_error("AccessDenied", "GetAccountSummary")
        iam.run(r, fake_session(iam=client), False)
        r.regions_not_checked = [{"region": "eu-west-1", "reason": "not in the --region list"}]
        r.finalize()
        return r

    def test_partial_reports_say_partial_and_carry_the_coverage_table(self):
        r = self._partial()
        summary = exec_summary.generate(r)
        self.assertIn("did not complete every check", summary["posture"])
        self.assertIn("not a clean result", summary["posture"])
        self.assertIn("Coverage was partial", summary["key_risks"])
        comp = compliance.analyze(r)
        with tempfile.TemporaryDirectory() as d:
            h = html.generate(r, d, summary=summary, compliance_data=comp)
            with open(h) as f:
                page = f.read()
            j = json_export.generate(r, d, summary=summary, compliance_data=comp)
            with open(j) as f:
                data = json.load(f)
        self.assertIn("Partial", page)
        self.assertIn("No score", page)
        self.assertIn("root account MFA", page)
        self.assertIn("AccessDenied", page)
        self.assertIn("not in the --region list", page)
        self.assertIn("Coverage (2 not run)", page)
        self.assertIn("controls without a finding are not passes", page)
        self.assertIn(f"atarus-cloud v{atarus_cloud.__version__}", page)
        self.assertNotIn("v1.0.0", page)
        self.assertIsNone(data["overall_score"])
        self.assertEqual(data["coverage_status"], "partial")
        self.assertEqual(data["checks_not_run"], 2)
        self.assertEqual(data["version"], atarus_cloud.__version__)
        self.assertIn("no score", data["score_note"])
        self.assertIsNone(data["remediation_script"])
        self.assertEqual(data["regions_not_checked"][0]["region"], "eu-west-1")
        not_run = [c for c in data["coverage"] if c["status"] == "not_run"]
        self.assertEqual(not_run[0]["check"], "root account MFA")

    def test_complete_report_shows_the_score(self):
        r = AuditResult(provider="aws", account_id="123456789012")
        iam.run(r, fake_session(iam=quiet_iam()), False)
        r.finalize()
        summary = exec_summary.generate(r)
        self.assertIn("100 out of 100", summary["posture"])
        with tempfile.TemporaryDirectory() as d:
            h = html.generate(r, d, summary=summary, compliance_data=compliance.analyze(r))
            with open(h) as f:
                page = f.read()
        self.assertIn("Score /100 (every check ran)", page)
        self.assertIn("Every check ran in every selected region.", page)
        self.assertNotIn("Partial", page)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class CliTests(unittest.TestCase):
    """End to end through click with every AWS client faked and the socket guarded."""

    def _run(self, args, enabled=("eu-west-1", "us-west-1"), iam_client=None, enumeration_error=None):
        base = fake_session("us-east-1", iam=iam_client or quiet_iam())
        identity = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/tester"}

        def regions(session):
            if enumeration_error:
                raise enumeration_error
            return list(enabled)

        def per_region(profile, region):
            return fake_session(region)

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(aws_auth, "get_session", return_value=(base, identity)))
            stack.enter_context(mock.patch.object(aws_auth, "enabled_regions", side_effect=regions))
            stack.enter_context(mock.patch.object(aws_auth, "session_for_region", side_effect=per_region))
            stack.enter_context(mock.patch.object(aws_auth, "get_account_alias", return_value="lab"))
            stack.enter_context(_NetworkGuard())
            stack.enter_context(_quiet_console())
            out = stack.enter_context(tempfile.TemporaryDirectory())
            result = CliRunner().invoke(cli.main, list(args) + ["--format", "json", "-o", out])
            data = None
            json_path = os.path.join(out, "atarus-cloud-123456789012.json")
            if os.path.exists(json_path):
                with open(json_path) as f:
                    data = json.load(f)
            scripts = [n for n in os.listdir(out) if n.endswith(".sh")]
        return result, data, scripts

    def test_default_run_covers_every_enabled_region_and_scores(self):
        result, data, scripts = self._run(["-p", "aws"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(data["regions"], ["eu-west-1", "us-west-1"])
        self.assertEqual(data["regions_not_checked"], [])
        self.assertEqual(data["coverage_status"], "complete")
        self.assertIsInstance(data["overall_score"], int)
        regions_seen = {c["region"] for c in data["coverage"]}
        self.assertEqual(regions_seen, {"global", "eu-west-1", "us-west-1"})
        self.assertEqual(scripts, [], "no remediation script without --remediation-script")

    def test_explicit_region_lists_the_others_as_not_checked_and_withholds_the_score(self):
        result, data, _ = self._run(["-p", "aws", "--region", "us-west-1"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(data["regions"], ["us-west-1"])
        self.assertEqual(data["regions_not_checked"], [{"region": "eu-west-1", "reason": "not in the --region list"}])
        self.assertEqual(data["coverage_status"], "partial")
        self.assertIsNone(data["overall_score"])

    def test_region_listing_failure_is_recorded(self):
        result, data, _ = self._run(["-p", "aws"], enumeration_error=aws_error("UnauthorizedOperation", "DescribeRegions"))
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(data["regions"], ["us-east-1"])
        self.assertEqual(data["regions_not_checked"][0]["region"], "all other regions")
        self.assertIn("DescribeRegions", data["regions_not_checked"][0]["reason"])
        self.assertIsNone(data["overall_score"])

    def test_only_and_skip_are_recorded(self):
        result, data, _ = self._run(["-p", "aws", "--only", "iam"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(data["coverage_status"], "partial")
        reasons = {c["detail"] for c in data["coverage"] if c["status"] == "not_run"}
        self.assertEqual(reasons, {"not listed in --only"})

    def test_remediation_script_is_opt_in(self):
        client = quiet_iam()
        client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
        result, data, scripts = self._run(["-p", "aws", "--remediation-script"], iam_client=client)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(scripts, ["remediation-123456789012.sh"])
        self.assertEqual(data["remediation_script"], "remediation-123456789012.sh")

    def test_unknown_module_is_a_usage_error(self):
        result, _, _ = self._run(["-p", "aws", "--skip", "nope"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Unknown module", result.output)

    def test_azure_without_the_extra_fails_clearly_before_any_auth(self):
        with mock.patch.object(cli, "missing_azure_packages", return_value=["azure-identity", "azure-mgmt-sql"]), \
             mock.patch("atarus_cloud.providers.azure.auth.get_credential", side_effect=AssertionError("auth reached")), \
             _NetworkGuard(), _quiet_console():
            result = CliRunner().invoke(cli.main, ["-p", "azure"])
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("pip install 'atarus-cloud[azure]'", result.output)
        self.assertIn("azure-mgmt-sql", result.output)

    def test_pdf_without_the_extra_fails_clearly(self):
        with mock.patch.object(cli, "pdf_available", return_value=False), _NetworkGuard(), _quiet_console():
            result = CliRunner().invoke(cli.main, ["-p", "aws", "--format", "pdf"])
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("atarus-cloud[pdf]", result.output)

    def test_version_and_list_modules_need_no_credentials(self):
        with _NetworkGuard():
            v = CliRunner().invoke(cli.main, ["--version"])
            m = CliRunner().invoke(cli.main, ["--list-modules"])
        self.assertEqual(v.exit_code, 0)
        self.assertIn(atarus_cloud.__version__, v.output)
        self.assertEqual(m.exit_code, 0)
        self.assertIn("cosmosdb", m.output)

    def test_no_credentials_is_a_message_not_a_traceback(self):
        from botocore.exceptions import NoCredentialsError

        fake_boto_session = mock.MagicMock()
        fake_boto_session.region_name = "us-east-1"
        fake_boto_session.client.return_value.get_caller_identity.side_effect = NoCredentialsError()
        with mock.patch.object(aws_auth.boto3, "Session", return_value=fake_boto_session), _NetworkGuard(), _quiet_console():
            result = CliRunner().invoke(cli.main, ["-p", "aws", "--format", "json"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No AWS credentials found", result.output)
        self.assertNotIn("Traceback", result.output)


class LazyImportTests(unittest.TestCase):
    def test_cli_import_pulls_in_neither_azure_sdk_nor_weasyprint(self):
        pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(atarus_cloud.__file__)))
        code = (
            "import sys; import atarus_cloud.cli; "
            "print(sorted(m for m in sys.modules if m.startswith('azure') or m.startswith('weasyprint')))"
        )
        env = dict(os.environ, PYTHONPATH=pkg_root)
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "[]")


if __name__ == "__main__":
    unittest.main()
