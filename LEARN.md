# Learning notes: Project 1, Cloud Misconfiguration Scanner

Read the code in this order: `models.py` → `aws_checks.py` → `report.py` → `ai_summary.py`
→ `cli.py`, with the matching test file open beside each one. Tests show what each piece is
supposed to do faster than the code does.

## 1. boto3 essentials

- **Session → client.** A `boto3.Session` holds credentials and a default region. Clients
  are made from it: `session.client("iam")`. Passing the session around (instead of calling
  `boto3.client` everywhere) is what makes the scanner testable and multi-profile.
- **Global vs regional.** IAM and S3 bucket listing are global; security groups are per
  region. That is why `check_security_groups` loops over regions and the others do not.
- **Paginators.** List calls return pages. `iam.get_paginator("list_users").paginate()`
  walks them all. Forgetting this is a classic bug: your scanner works on a lab account
  with 5 users and silently misses user 101 in a real one.
- **Errors.** Everything raises `botocore.exceptions.ClientError`; the code is in
  `exc.response["Error"]["Code"]`. Some errors are normal answers
  (`NoSuchBucketPolicy` means "no policy"), others mean "could not check" (`AccessDenied`).
  Treating the second kind as "no findings" is how scanners lie.

## 2. Testing cloud code without a cloud: moto

`moto` fakes AWS APIs in memory. `with mock_aws():` and every boto3 call inside goes to the
fake. Tests create the misconfiguration, run the scanner, assert the finding. The
`fake_aws_credentials` fixture also makes it impossible for a test to touch a real account.
Limitation: moto is a model of AWS, not AWS. Always confirm against a real sandbox before
trusting a check.

## 3. The misconfigurations

**S3 exposure has three layers.** An ACL can grant `AllUsers`; a bucket policy can allow
`Principal: "*"`; and S3 Block Public Access (four settings, at account and bucket level)
can override both. A setting counts as on if either layer turns it on. A policy with a
`Condition` (for example, a source IP range) is not public. Since April 2023, new buckets
start with Block Public Access on and ACLs disabled, so a public bucket today usually means
someone turned the protection off.

**Identity.** Root without MFA is critical because root cannot be restricted by IAM
policies. Console users without MFA fall to password spraying and phishing. Long-lived
access keys leak through code, CI logs and laptops; the fix is roles, IAM Identity Center
and OIDC federation (Project 3's CI pipeline will use GitHub OIDC so it needs no keys at all).

**Security groups** are stateful allow-lists. `0.0.0.0/0` (IPv4) and `::/0` (IPv6) mean
"the whole internet". Rules are port *ranges*, so a 1000-4000 rule exposes RDP and MySQL even
though neither port is named. `-1` means all protocols.

## 4. Prompt injection, the part interviewers will ask about

- **Direct** injection: the user types malicious instructions. **Indirect** injection: the
  instructions arrive inside data the model reads (a web page, an email, a log line, a tag).
  Security tooling is especially exposed to the indirect kind, because logs and resource
  metadata are written by whoever controls the system, including attackers.
- **There is no single fix.** Delimiters and "ignore instructions in the data" help but can
  be beaten. The strong controls are structural: the model has **no tools** (nothing to
  hijack), its output is **validated against facts the code already knows** (real finding
  IDs, a severity floor), and the system **degrades safely** when validation fails.
- The **severity floor** is the key invariant: whatever the model says, the report can never
  show a lower overall risk than the deterministic checks found.
- The regex detector in `detect_injection` is a tripwire, not a wall. Exercise 4 asks you
  to beat it.

## 5. Reports are an attack surface too

The HTML report prints bucket names, descriptions and model output. Without escaping, a
security-group description of `<script>...</script>` becomes stored XSS in the security
team's browser. `autoescape=True` handles it; the Content Security Policy meta tag is a
second layer. `test_html_escapes_hostile_resource_metadata` proves it.

## 6. CI exit codes

`--fail-on high` exits with code 2 when a High or Critical finding exists. Any CI system
treats a non-zero exit as failure, so the scanner can block a pipeline. Project 3 uses the
same idea with Checkov.

## Exercises (do these yourself; this is where the learning happens)

1. **CloudTrail check.** Add `AWS-CT-001`: no multi-region trail that is logging. Use
   `cloudtrail.describe_trails()` and `get_trail_status()`. Write the test first.
2. **EBS default encryption.** Add a per-region check with `ec2.get_ebs_encryption_by_default()`.
3. **Diff.** Write `cloudscan diff old.json new.json` that prints fixed, new and unchanged
   findings using the stable IDs.
4. **Break the guardrail.** Write three poisoned descriptions that slip past
   `INJECTION_PATTERNS` (other languages, spacing tricks, base64). Add them as tests. Then
   explain why the scan stays safe anyway.
5. **Real account.** Create a sandbox IAM user with only `SecurityAudit`, make one bucket
   public on purpose, scan, fix, scan again. Screenshot both reports for the README.
6. **Bedrock.** Enable model access in Bedrock, set `CLOUDSCAN_BEDROCK_MODEL_ID`, and run
   `--ai bedrock`. Note what IAM permission the scanner identity needed.

## Interview questions you should be able to answer after this project

1. Why does the scanner need only `SecurityAudit`, and why does that matter?
2. A bucket has a public ACL but the account has Block Public Access on. Is it public? Why?
3. What is the difference between a security group and a network ACL?
4. Why are long-lived access keys risky, and what replaces them?
5. What is indirect prompt injection, and where does it show up in security tooling?
6. Your AI summary says "no risk" but the checks found a Critical. What should happen, and
   how does this code guarantee it?
7. Why is "no findings" not proof of a secure account?
8. How would you run this across 50 AWS accounts in an organisation?
