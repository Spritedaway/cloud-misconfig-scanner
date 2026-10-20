from conftest import block_all, by_check, open_sg, public_policy, world

from cloudscan.aws_checks import mask_key, policy_is_public
from cloudscan.models import Severity

# ---------------------------------------------------------------- S3


def test_public_acl_bucket_is_flagged(session, scan):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="public-acl")
    s3.put_bucket_acl(Bucket="public-acl", ACL="public-read")
    findings, _ = scan()
    hits = by_check(findings, "AWS-S3-001")
    assert [f.resource_id for f in hits] == ["public-acl"]
    assert hits[0].severity == Severity.HIGH
    assert "AllUsers" in hits[0].evidence["public_via"][0]


def test_public_policy_bucket_is_flagged(session, scan):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="public-policy")
    s3.put_bucket_policy(Bucket="public-policy", Policy=public_policy("public-policy"))
    findings, _ = scan()
    assert [f.resource_id for f in by_check(findings, "AWS-S3-001")] == ["public-policy"]


def test_bucket_block_public_access_suppresses_public_acl(session, scan):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="locked")
    s3.put_bucket_acl(Bucket="locked", ACL="public-read")
    block_all(session, bucket="locked")
    findings, _ = scan()
    assert not by_check(findings, "AWS-S3-001")
    assert not by_check(findings, "AWS-S3-002")


def test_account_level_block_covers_every_bucket(session, scan):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="policy-public")
    s3.put_bucket_policy(Bucket="policy-public", Policy=public_policy("policy-public"))
    block_all(session)  # account level only
    findings, _ = scan()
    assert not [f for f in findings if f.check_id.startswith("AWS-S3")]


def test_private_bucket_without_block_public_access_is_medium(session, scan):
    session.client("s3").create_bucket(Bucket="private-but-unguarded")
    findings, _ = scan()
    hits = by_check(findings, "AWS-S3-002")
    assert hits and hits[0].severity == Severity.MEDIUM


def test_policy_with_condition_is_not_public():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            }
        ]
    }
    assert not policy_is_public(policy)
    assert policy_is_public({"Statement": {"Effect": "Allow", "Principal": {"AWS": ["*"]}}})


# ---------------------------------------------------------------- IAM


def test_root_without_mfa_is_critical(scan):
    findings, _ = scan()
    hits = by_check(findings, "AWS-IAM-001")
    assert hits and hits[0].severity == Severity.CRITICAL


def test_console_user_without_mfa_is_flagged(session, scan):
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Correct-Horse-9!")
    iam.create_user(UserName="api-only")  # no console password: not this check's concern
    findings, _ = scan()
    assert [f.resource_id for f in by_check(findings, "AWS-IAM-002")] == ["alice"]


def test_unused_access_key_after_90_days(session, scan):
    iam = session.client("iam")
    iam.create_user(UserName="ci")
    key = iam.create_access_key(UserName="ci")["AccessKey"]["AccessKeyId"]
    fresh, _ = scan(days_later=0)
    assert not by_check(fresh, "AWS-IAM-003")
    stale, _ = scan(days_later=120)
    hits = by_check(stale, "AWS-IAM-003")
    assert len(hits) == 1
    assert hits[0].evidence["last_used"] == "never"
    assert key not in str(hits[0].to_dict())  # full key ID never lands in the report


def test_inactive_key_is_ignored(session, scan):
    iam = session.client("iam")
    iam.create_user(UserName="old")
    key = iam.create_access_key(UserName="old")["AccessKey"]["AccessKeyId"]
    iam.update_access_key(UserName="old", AccessKeyId=key, Status="Inactive")
    findings, _ = scan(days_later=200)
    assert not by_check(findings, "AWS-IAM-003")


def test_mask_key():
    assert mask_key("AKIAABCDEFGHIJKLMNOP") == "AKIA...MNOP"


# ---------------------------------------------------------------- Security groups


def test_ssh_open_to_world_is_high(session, scan):
    gid = open_sg(session, "bastion", "jump box", [world("tcp", 22)])
    findings, _ = scan()
    hits = by_check(findings, "AWS-EC2-002")
    assert [f.resource_id for f in hits] == [gid]
    assert hits[0].evidence["ports"] == {"22": "SSH"}


def test_ipv6_ssh_open_to_world_is_flagged(session, scan):
    ipv6_rule = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }
    gid = open_sg(session, "v6-bastion", "ipv6 jump box", [ipv6_rule])
    findings, _ = scan()
    hits = by_check(findings, "AWS-EC2-002")
    assert [f.resource_id for f in hits] == [gid]
    assert hits[0].evidence["sources"] == ["::/0"]


def test_port_range_covering_rdp_and_db_is_caught(session, scan):
    gid = open_sg(session, "wide", "range", [world("tcp", 1000, 4000)])
    findings, _ = scan()
    assert by_check(findings, "AWS-EC2-002")[0].evidence["ports"] == {"3389": "RDP"}
    assert by_check(findings, "AWS-EC2-003")[0].evidence["ports"] == {
        "1433": "MSSQL",
        "3306": "MySQL",
    }
    assert {f.resource_id for f in by_check(findings, "AWS-EC2-003")} == {gid}


def test_all_traffic_is_critical(session, scan):
    open_sg(session, "yolo", "temp", [world("-1")])
    findings, _ = scan()
    hits = by_check(findings, "AWS-EC2-001")
    assert hits and hits[0].severity == Severity.CRITICAL


def test_https_and_private_cidr_are_not_flagged(session, scan):
    open_sg(session, "web", "public site", [world("tcp", 443)])
    open_sg(session, "office-ssh", "office", [world("tcp", 22, cidr="203.0.113.10/32")])
    findings, _ = scan()
    assert not [f for f in findings if f.check_id.startswith("AWS-EC2")]


def test_findings_sorted_most_severe_first(session, scan):
    open_sg(session, "bastion", "jump box", [world("tcp", 22)])
    session.client("s3").create_bucket(Bucket="unguarded")
    findings, _ = scan()
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, reverse=True)


def test_finding_ids_are_stable_across_scans(session, scan):
    open_sg(session, "bastion", "jump box", [world("tcp", 22)])
    first, _ = scan()
    second, _ = scan()
    assert [f.id for f in first] == [f.id for f in second]
