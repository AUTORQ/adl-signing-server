# Several manufacturing partners on one server

One deployment can serve every manufacturing partner. Each partner gets one
environment per stage, named `<partner>-<stage>`, with its own intermediate
CA (KMS key) and O=:

```json
[
  {"name": "edge-labs-dev",  "partner": "edge-labs", "stage": "dev",  "organization": "EDGE Labs",
   "kms_key_id": "...", "device_prefix": "DVTADL", "device_id_from_chip": true, "require_chip_id": true,
   "validity_days": 3650, "allow_key_escrow": true},
  {"name": "edge-labs-prod", "partner": "edge-labs", "stage": "prod", "organization": "EDGE Labs",
   "kms_key_id": "...", "device_prefix": "DVTADL", "device_id_from_chip": true, "require_chip_id": true,
   "validity_days": 3650}
]
```

## Who acts for which partner

Bindings in `ADL_AUTH_POLICY` take `accounts`. Give each partner its own AWS
account and bind it to that partner's environments only:

```json
{"accounts": ["111111111111", "222222222222"],
 "bindings": [
   {"accounts": ["111111111111"], "roles": ["AWSReservedSSO_AdministratorAccess_*"], "permissions": ["*"]},
   {"accounts": ["222222222222"], "roles": ["*"], "users": ["*"],
    "permissions": ["edge-labs-dev:issue", "edge-labs-dev:read", "edge-labs-prod:issue", "edge-labs-prod:read", "edge-labs-prod:provision"]}
 ]}
```

Role and user names are only unique within an account. With more than one
account, scope every binding, or a partner can create a role named like
someone else's and match their binding.

`ca:admin` (intermediate CSR and install), `admin:import` and `audit:read`
are global: keep them for the operator's own staff.

## Device ids and stages

With `device_id_from_chip`, the device id is the partner's prefix + the
chip's MAC in upper case (`DVTADL3C71BF4A12E0`), so a board has the same id
in dev and prod. Every certificate then needs the MAC, and there is no
counter. A device belongs to one environment at a time: issuing in another
stage of the same partner is refused (`env_mismatch`) unless the request
sets `move`, which revokes the device's certificates in the old stage
(`cessationOfOperation`) once the new one is recorded. Moving needs
`revoke` on the old environment.

All stages of a partner must share the prefix and id scheme, and partners'
prefixes must not overlap; the server refuses to start otherwise.

## The CLI

`/v1/whoami` lists the environments the caller may use, with their partner
and stage. `--env` takes a stage or a full name: a partner's people type
`adl mint --env dev --mac ...` and land in their own environment; people
who may act for several partners add `--partner <slug>` or set a default
with `adl configure --partner <slug>`.

```bash
adl whoami
adl mint --env dev --port /dev/ttyUSB0             # MAC read with esptool
adl eol provision --env prod --station line-1 --port /dev/ttyUSB0 [--move]
adl mint --partner acme --env dev --mac 00:11:22:33:44:55   # operator staff
adl ca csr --partner acme --env prod --cn "ACME Intermediate CA prod" --org ACME
```

## One signer per stage

A dev signer and a prod signer (in different AWS accounts) work too: each
holds only its own stage's environments. MAC-based ids can't collide across
them, but neither knows what the other issued, so a board can hold a dev
and a prod certificate at once, and `move` doesn't apply. Configure both
servers and `--env` picks one:

```bash
adl configure --stage dev  --url https://signer.dev.autorq.com  --region us-east-1 --audience autorq-signer:dev  --profile edge-labs-dev
adl configure --stage prod --url https://signer.prod.autorq.com --region us-east-1 --audience autorq-signer:prod --profile edge-labs-prod
adl mint --env dev --mac 3c:71:bf:4a:12:e0
adl show DVTADL3C71BF4A12E0 --env prod
```

`/healthz` no longer lists environments, so anonymous callers can't
enumerate partners.
