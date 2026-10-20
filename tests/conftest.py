import json
from datetime import timedelta

import boto3
import pytest
from moto import mock_aws

from cloudscan.aws_checks import PAB_KEYS, AwsScanner


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    """Make it impossible for a test to touch a real AWS account."""
    for var in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def session():
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")


@pytest.fixture
def scan(session):
    """Run the scanner. `days_later` moves the scanner's clock forward to age access keys."""

    def _scan(days_later: int = 0):
        scanner = AwsScanner(session=session, regions=["us-east-1"])
        scanner.now = scanner.now + timedelta(days=days_later)
        return scanner.run(), scanner

    return _scan


def by_check(findings, check_id):
    return [f for f in findings if f.check_id == check_id]


def block_all(session, bucket=None):
    cfg = {k: True for k in PAB_KEYS}
    if bucket:
        session.client("s3").put_public_access_block(
            Bucket=bucket, PublicAccessBlockConfiguration=cfg
        )
    else:
        session.client("s3control").put_public_access_block(
            AccountId="123456789012", PublicAccessBlockConfiguration=cfg
        )


def public_policy(bucket):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }
            ],
        }
    )


def open_sg(session, name, description, perms):
    ec2 = session.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    gid = ec2.create_security_group(GroupName=name, Description=description, VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
    return gid


def world(proto, low=None, high=None, cidr="0.0.0.0/0"):
    perm = {"IpProtocol": proto, "IpRanges": [{"CidrIp": cidr}]}
    if low is not None:
        perm.update(FromPort=low, ToPort=high if high is not None else low)
    return perm
