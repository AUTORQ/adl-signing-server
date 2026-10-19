# Operations

## Deploying

Prereqs: Terraform 1.6+, Go 1.26+, AWS credentials for the target account
(ideally a dedicated one), and an S3 backend for state.

```sh
make dist                                   # dist/adl-signer-lambda.zip, dist/adl-signer-linux-arm64, dist/cli/*
cd deploy/terraform/environments/example    # copy this dir per real environment
cp terraform.tfvars.example terraform.tfvars
$EDITOR versions.tf terraform.tfvars        # backend, region, environments, cert_organization, deployment_mode, bindings
terraform init
terraform plan -out plan
terraform apply plan
terraform output cli_configure
```

Then run the CA ceremony (docs/ca-ceremony.md) for each environment, import
any devices you certified before, and hand the `cli_configure` line to
developers and the factory. To serve several manufacturing partners from one
deployment, see docs/partners.md.

### Choosing a mode

`deployment_mode = "lambda" | "ec2" | "both"`. See the table in
architecture.md. Switching later is just a variable change. The keys,
registry and archive stay put, and only the front end is added or removed.

EC2 needs `vpc_id`, private `instance_subnet_ids` with outbound HTTPS (NAT,
or VPC endpoints for STS, KMS, DynamoDB, S3 and logs, plus SSM,
ssmmessages and ec2messages if you turn on Session Manager), `alb_subnet_ids`, and an ACM certificate. Point a DNS name at
`alb_dns_name`.

For Lambda with your own hostname, set `lambda_domain_name` and
`lambda_certificate_arn`, then point a CNAME at the `domain_target` output.
This turns off the default `execute-api` URL.

### Binding people

Prefer IAM Identity Center permission sets. The `adl-*` roles are off by
default, and when you turn them on you must name exactly who may assume them
(`client_role_trusted_principal_arns`); there's no account-wide trust.

```hcl
auth_bindings = [
  { roles = ["AWSReservedSSO_ADLDeveloper_*"], permissions = ["dev:issue", "dev:read", "dev:key-read"] },
  { roles = ["AWSReservedSSO_ADLCAAdmin_*"],   permissions = ["*"] },
]
```

The permission sets themselves need no AWS permissions for this service.

## Upgrading

```sh
git pull && make dist
terraform apply
```

Lambda picks up the new zip through its hash. On EC2 the binary's hash is
part of the S3 key and the launch template, so `apply` creates a new
template version and the ASG rolls the instances (50% minimum healthy).

## Day to day

| task | command |
|---|---|
| who did what today | `adl audit` / `adl audit --day 2026-10-01` |
| is a CA close to expiry | `adl ca status --stage prod` |
| look at a device | `adl show GLXADL031` |
| revoke | `adl revoke GLXADL031 --reason keyCompromise` |
| server logs (Lambda) | CloudWatch `/aws/lambda/adl-signer`, API access logs in `/aws/apigateway/adl-signer` |
| server logs (EC2) | CloudWatch `/adl/adl-signer`, one stream per instance |
| shell on an instance | set `enable_ssm_session_access = true`, apply, `aws ssm start-session --target i-0123...`, then turn it off again |

Every log line is JSON and carries a `request_id`. The CLI prints the request
ID on errors, so grep for it.

## Common errors

| error code | meaning | fix |
|---|---|---|
| `unauthenticated` | the token was rejected (expired creds, clock skew over 5 minutes, wrong audience/region) | `aws sso login`, check clock, re-run `adl configure` |
| `forbidden` | identity is fine but has no binding / lacks the permission | add a binding in Terraform |
| `ca_not_configured` | the env's intermediate isn't installed | run the ceremony |
| `chip_already_assigned` | that chip already has an identity | see the EoL failure table |
| `device_exists` | the ID already has a cert | `--replace`, or leave the ID empty |
| `serial_mismatch` on provision | the station tried to confirm an old serial | re-run provisioning on that board |
| `auth_unavailable` | the server couldn't reach STS | transient; check NAT/VPC endpoints on EC2 |

## Backup and restore

- DynamoDB: PITR (35 days) plus a daily AWS Backup. Restore to a new table,
  then point `ADL_TABLE_NAME` at it (Terraform: import the restored table or
  change the name).
- S3: versioning and Object Lock mean "deleted" objects are still there as
  versions. AWS Backup takes a daily recovery point as well.
- KMS keys can't be backed up and don't need to be. They're
  `prevent_destroy` with a 30-day deletion window. If a deletion is ever
  scheduled, **cancel it**. A destroyed CA key can't be recovered; you'd
  need a new intermediate and every device re-keyed.

## Local development

```sh
make local                                   # server with throwaway CA on 127.0.0.1:8080
adl configure --url http://127.0.0.1:8080 --local
adl mint
```

Local mode refuses to listen on anything but loopback, and its certificates
chain to a root that only exists in that process.
