# Security notes

## What we're protecting, in order

1. **The intermediate CA keys.** Whoever can sign with them can mint a
   device the cloud will trust.
2. **Production device private keys.** Each one is a working device
   identity.
3. **The registry and archive.** These record which identities exist, and
   they're the only way to recover dev keys.
4. **Escrowed dev keys.** Lower value, but still device identities in the
   dev environment.

## Controls

### CA keys

- Generated in KMS (FIPS 140-validated HSMs), non-exportable. There's no
  file to steal.
- The key policy grants `kms:Sign` to the service role(s) only, plus an
  explicit Deny for everyone else. Key admins can manage the key but can't
  sign. The key is `prevent_destroy` with a 30-day deletion window.
- Every certificate the signer gets back from KMS is verified against the
  issuer before it's returned.
- Every `Sign` call is in CloudTrail. The audit log ties each one to a
  person or station.

### Who can issue

- No shared secrets. Identity is the caller's IAM principal, checked by STS
  on every request (see architecture.md for the token binding).
- Least-privilege bindings: developers can't touch prod, stations can't
  revoke, re-key shipped boards or read keys.
- Prod certs need a chip MAC, and a MAC is bound to exactly one device.
- Rate limiting: API Gateway throttling and reserved concurrency on Lambda,
  WAF rate limits on the ALB.

### Device keys

- Prod keys are generated on the station, held in memory and a tmpfs dir
  for the few seconds of the flash, then wiped. The server rejects any
  attempt to escrow a prod key.
- With the DS peripheral flow, the key on the chip is encrypted under an
  eFuse HMAC key and is only usable through the peripheral.
- Dev keys are generated on the developer's machine and, by default,
  escrowed.

### Escrow (the deliberate trade-off)

Storing private keys centrally isn't best practice. We do it for **dev only**
because developers kept losing them, and a lost dev key costs more time than
it's worth protecting. Mitigations:

- Escrowed keys are encrypted with a dedicated KMS key (`alias/*-escrow`).
  Only the service role, the AWS Backup role and named break-glass roles can
  decrypt, enforced by both the key policy and the bucket policy.
- A key comes back only through the API, only to holders of
  `dev:key-read`, and every retrieval is an audit event (`key.retrieve`).
- Escrow can be turned off per environment (`allow_key_escrow`). It's off
  for prod by default, and the server enforces it.
- Dev certs chain to the dev intermediate, so the cloud can keep dev
  identities out of prod.

### Data at rest and in transit

- DynamoDB, S3 and CloudWatch Logs are all encrypted with a customer-managed
  KMS key with rotation on.
- The S3 bucket is TLS-only, has all public access blocked and ACLs
  disabled, and is versioned with Object Lock (governance, 10 years
  by default). It can't be silently overwritten or emptied.
- DynamoDB has point-in-time recovery and deletion protection. AWS Backup
  takes daily backups of both, with an optional cross-region copy.
- The service IAM policy has no delete permissions at all.
- TLS 1.2+ at API Gateway, and TLS 1.3/1.2 policy on the ALB.

### EC2 specifics

No SSH: shell access is SSM Session Manager, which is audited. IMDSv2
only, hop limit 1. Encrypted EBS. The binary is fetched from S3 and checked
against a SHA-256 pinned in the launch template. It runs as an
unprivileged user with a locked-down systemd sandbox. The instance security
group only allows the ALB.

## Things this repo doesn't do (but you should)

- **Alarms.** Add CloudWatch alarms or EventBridge rules for: assumption of
  a break-glass role; any `kms:Sign` on the CA keys by a principal other
  than the service role (it should be impossible, so alert if it happens);
  `ca.install` and `key.retrieve` audit events; and 4xx/5xx spikes.
- **SCPs** in the AWS org preventing `kms:ScheduleKeyDeletion` on the CA
  keys and `s3:BypassGovernanceRetention`, except from a break-glass role.
- **Separate account.** Run this in its own AWS account with very few
  admins. It's the most sensitive thing in the device stack.
- **Station hardening.** Use full-disk encryption, a dedicated OS user, and
  IAM Roles Anywhere with the station key in a TPM.
- **Firmware.** Secure Boot v2 and flash encryption at end of line (see
  eol-provisioning.md).

## Break glass

If the service is down and someone urgently needs an escrowed dev key, a
role listed in `break_glass_role_arns` can read
`s3://<archive>/escrow/dev/<device>/<serial>/private-key.pem` directly.
That bypasses the app's audit log but still shows up in CloudTrail (S3 data
events, if enabled, plus the KMS Decrypt). Alarm on it.

There is no break-glass path for the CA keys. That's by design.
