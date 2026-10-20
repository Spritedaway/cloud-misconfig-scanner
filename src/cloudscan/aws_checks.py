"""AWS checks. Every call here is read-only (List*/Get*/Describe*).

The scanner only needs the AWS managed policy `SecurityAudit`. It never changes anything.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from .models import Finding, Severity

PROVIDER = "aws"

_GROUPS = "http://acs.amazonaws.com/groups/global/"
PUBLIC_GRANTEES = {
    _GROUPS + "AllUsers": "AllUsers (anyone on the internet)",
    _GROUPS + "AuthenticatedUsers": "AuthenticatedUsers (any AWS account)",
}
PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DATA_PORTS = {
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}
WORLD = {"0.0.0.0/0", "::/0"}

KEY_IDLE_DAYS = 90
KEY_ROTATE_DAYS = 90

REF_S3_BPA = (
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
)
REF_IAM_MFA = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
REF_IAM_KEYS = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
REF_SG = "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-group-rules.html"


def mask_key(key_id: str) -> str:
    """Access key IDs are not secrets, but reports travel, so show only enough to identify."""
    return f"{key_id[:4]}...{key_id[-4:]}" if len(key_id) > 8 else "****"


def policy_is_public(policy: dict) -> bool:
    """True when any Allow statement grants Principal '*' with no Condition narrowing it."""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow" or stmt.get("Condition"):
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws = principal.get("AWS")
            if aws == "*" or (isinstance(aws, list) and "*" in aws):
                return True
    return False


class AwsScanner:
    def __init__(
        self,
        session: boto3.Session | None = None,
        regions: list[str] | None = None,
        now: datetime | None = None,
    ) -> None:
        self.session = session or boto3.Session()
        self.regions = regions or [self.session.region_name or "us-east-1"]
        self.now = now or datetime.now(timezone.utc)
        # A check that fails (missing permission, throttling) is recorded, never silently
        # skipped: "no findings" must not be confused with "could not look".
        self.errors: list[str] = []
        self._account_id: str | None = None

    # ------------------------------------------------------------------ helpers
    @property
    def account_id(self) -> str:
        if self._account_id is None:
            self._account_id = self.session.client("sts").get_caller_identity()["Account"]
        return self._account_id

    def all_regions(self) -> list[str]:
        ec2 = self.session.client("ec2", region_name=self.regions[0])
        return sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])

    def _safe(self, name: str, check: Callable[[], Iterable[Finding]]) -> list[Finding]:
        try:
            return list(check())
        except ClientError as exc:
            self.errors.append(f"{name}: {exc.response['Error'].get('Code', 'ClientError')}")
            return []

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._safe("s3_public_access", self.check_s3_public_access)
        findings += self._safe("iam_mfa", self.check_iam_mfa)
        findings += self._safe("iam_access_keys", self.check_access_keys)
        for region in self.regions:
            findings += self._safe(
                f"security_groups[{region}]", lambda r=region: self.check_security_groups(r)
            )
        return sorted(findings, key=lambda f: (-f.severity, f.check_id, f.resource_id))

    # ----------------------------------------------------------------------- S3
    def _account_pab(self) -> dict:
        s3control = self.session.client("s3control", region_name=self.regions[0])
        try:
            cfg = s3control.get_public_access_block(AccountId=self.account_id)
            return cfg["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return {}
            raise

    @staticmethod
    def _bucket_pab(s3, bucket: str) -> dict:
        try:
            return s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return {}
            raise

    @staticmethod
    def _bucket_policy(s3, bucket: str) -> dict | None:
        try:
            return json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return None
            raise

    @staticmethod
    def _bucket_region(s3, bucket: str) -> str:
        loc = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint")
        return loc or "us-east-1"

    def check_s3_public_access(self) -> Iterable[Finding]:
        s3 = self.session.client("s3")
        account_pab = self._account_pab()
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            region = self._bucket_region(s3, name)
            bucket_pab = self._bucket_pab(s3, name)
            # Block Public Access works in layers: a setting is on if the account OR the
            # bucket turns it on.
            effective = {k: bool(account_pab.get(k) or bucket_pab.get(k)) for k in PAB_KEYS}

            public_via: list[str] = []
            if not effective["IgnorePublicAcls"]:
                for grant in s3.get_bucket_acl(Bucket=name).get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI")
                    if uri in PUBLIC_GRANTEES:
                        public_via.append(
                            f"ACL grants {grant['Permission']} to {PUBLIC_GRANTEES[uri]}"
                        )
            if not effective["RestrictPublicBuckets"]:
                policy = self._bucket_policy(s3, name)
                if policy and policy_is_public(policy):
                    public_via.append("Bucket policy allows Principal '*' with no Condition")

            if public_via:
                yield Finding(
                    provider=PROVIDER,
                    check_id="AWS-S3-001",
                    title="S3 bucket is publicly accessible",
                    severity=Severity.HIGH,
                    resource_type="AWS::S3::Bucket",
                    resource_id=name,
                    region=region,
                    evidence={"public_via": public_via},
                    remediation=(
                        "Remove the public ACL grant or policy statement, then enable all four "
                        "S3 Block Public Access settings on the bucket (and ideally the account). "
                        "Serve public content through CloudFront with origin access control."
                    ),
                    references=(REF_S3_BPA,),
                )
            elif not all(effective.values()):
                yield Finding(
                    provider=PROVIDER,
                    check_id="AWS-S3-002",
                    title="S3 Block Public Access is not fully enabled",
                    severity=Severity.MEDIUM,
                    resource_type="AWS::S3::Bucket",
                    resource_id=name,
                    region=region,
                    evidence={"settings_off": [k for k, on in effective.items() if not on]},
                    remediation=(
                        "Turn on all four Block Public Access settings so a future ACL or "
                        "policy change cannot expose the bucket by accident."
                    ),
                    references=(REF_S3_BPA,),
                )

    # ---------------------------------------------------------------------- IAM
    def _users(self, iam) -> Iterable[dict]:
        for page in iam.get_paginator("list_users").paginate():
            yield from page["Users"]

    @staticmethod
    def _has_console_password(iam, user: str) -> bool:
        try:
            iam.get_login_profile(UserName=user)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                return False
            raise

    def check_iam_mfa(self) -> Iterable[Finding]:
        iam = self.session.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) != 1:
            yield Finding(
                provider=PROVIDER,
                check_id="AWS-IAM-001",
                title="Root user has no MFA",
                severity=Severity.CRITICAL,
                resource_type="AWS::Account",
                resource_id="root",
                region="global",
                evidence={"AccountMFAEnabled": summary.get("AccountMFAEnabled", 0)},
                remediation=(
                    "Enable MFA on the root user (a hardware key or passkey is best), "
                    "then stop using root for daily work."
                ),
                references=(REF_IAM_MFA,),
            )
        for user in self._users(iam):
            name = user["UserName"]
            if not self._has_console_password(iam, name):
                continue  # programmatic-only users are covered by the access-key check
            if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                yield Finding(
                    provider=PROVIDER,
                    check_id="AWS-IAM-002",
                    title="IAM user can sign in to the console without MFA",
                    severity=Severity.HIGH,
                    resource_type="AWS::IAM::User",
                    resource_id=name,
                    region="global",
                    evidence={"console_access": True, "mfa_devices": 0},
                    remediation=(
                        "Require MFA for this user, or better, move people to IAM Identity "
                        "Center (SSO) and remove long-lived IAM users."
                    ),
                    references=(REF_IAM_MFA,),
                )

    def check_access_keys(self) -> Iterable[Finding]:
        iam = self.session.client("iam")
        for user in self._users(iam):
            name = user["UserName"]
            for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue
                key_id = key["AccessKeyId"]
                created: datetime = key["CreateDate"]
                last_used = (
                    iam.get_access_key_last_used(AccessKeyId=key_id)
                    .get("AccessKeyLastUsed", {})
                    .get("LastUsedDate")
                )
                idle_days = (self.now - (last_used or created)).days
                age_days = (self.now - created).days
                evidence = {
                    "user": name,
                    "access_key": mask_key(key_id),
                    "created": created.date().isoformat(),
                    "last_used": last_used.date().isoformat() if last_used else "never",
                    "age_days": age_days,
                    "idle_days": idle_days,
                }
                if idle_days >= KEY_IDLE_DAYS:
                    yield Finding(
                        provider=PROVIDER,
                        check_id="AWS-IAM-003",
                        title=(
                            f"Active access key unused for {KEY_IDLE_DAYS}+ days"
                            if last_used
                            else f"Active access key never used in {KEY_IDLE_DAYS}+ days"
                        ),
                        severity=Severity.MEDIUM,
                        resource_type="AWS::IAM::AccessKey",
                        resource_id=f"{name}/{mask_key(key_id)}",
                        region="global",
                        evidence=evidence,
                        remediation=(
                            "Deactivate the key, wait to confirm nothing breaks, then delete it. "
                            "Prefer IAM roles or OIDC federation over long-lived keys."
                        ),
                        references=(REF_IAM_KEYS,),
                    )
                elif age_days >= KEY_ROTATE_DAYS:
                    yield Finding(
                        provider=PROVIDER,
                        check_id="AWS-IAM-004",
                        title=f"Access key older than {KEY_ROTATE_DAYS} days (not rotated)",
                        severity=Severity.LOW,
                        resource_type="AWS::IAM::AccessKey",
                        resource_id=f"{name}/{mask_key(key_id)}",
                        region="global",
                        evidence=evidence,
                        remediation=(
                            "Rotate the key: create a new one, switch callers, delete the old."
                        ),
                        references=(REF_IAM_KEYS,),
                    )

    # -------------------------------------------------------- Security groups
    def check_security_groups(self, region: str) -> Iterable[Finding]:
        ec2 = self.session.client("ec2", region_name=region)
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                yield from self._evaluate_sg(sg, region)

    def _evaluate_sg(self, sg: dict, region: str) -> Iterable[Finding]:
        all_traffic: set[str] = set()
        admin: dict[int, str] = {}
        data: dict[int, str] = {}
        sources: set[str] = set()

        for perm in sg.get("IpPermissions", []):
            world = {r.get("CidrIp") for r in perm.get("IpRanges", [])} | {
                r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])
            }
            world &= WORLD
            if not world:
                continue
            sources |= world
            protocol = str(perm.get("IpProtocol"))
            if protocol == "-1":
                all_traffic |= world
                continue
            if protocol not in {"tcp", "udp", "6", "17"}:
                continue
            low, high = perm.get("FromPort", 0), perm.get("ToPort", 65535)
            admin.update({p: n for p, n in ADMIN_PORTS.items() if low <= p <= high})
            data.update({p: n for p, n in DATA_PORTS.items() if low <= p <= high})

        base = {
            "group_name": sg.get("GroupName", ""),
            "description": sg.get("Description", ""),
            "vpc_id": sg.get("VpcId", ""),
            "sources": sorted(sources),
        }

        def finding(check_id, title, severity, extra, remediation):
            return Finding(
                provider=PROVIDER,
                check_id=check_id,
                title=title,
                severity=severity,
                resource_type="AWS::EC2::SecurityGroup",
                resource_id=sg["GroupId"],
                region=region,
                evidence={**base, **extra},
                remediation=remediation,
                references=(REF_SG,),
            )

        if all_traffic:
            yield finding(
                "AWS-EC2-001",
                "Security group allows ALL traffic from the internet",
                Severity.CRITICAL,
                {"protocol": "all"},
                "Delete the 0.0.0.0/0 all-traffic rule and allow only the ports and source "
                "ranges the workload needs.",
            )
        if admin:
            yield finding(
                "AWS-EC2-002",
                "Admin port (SSH/RDP) open to the internet",
                Severity.HIGH,
                {"ports": {str(p): n for p, n in sorted(admin.items())}},
                "Close SSH/RDP to the internet. Use AWS Systems Manager Session Manager, or "
                "restrict the source to a known IP range behind a VPN.",
            )
        if data:
            yield finding(
                "AWS-EC2-003",
                "Database or data-store port open to the internet",
                Severity.HIGH,
                {"ports": {str(p): n for p, n in sorted(data.items())}},
                "Data stores should never face the internet. Allow access only from the "
                "application's security group.",
            )
