# Several manufacturing partners on one server

One deployment can serve every manufacturing partner. AutorQ runs one per
stage (a dev signer and a prod signer, in different AWS accounts).

## Words

| Word | Means | Example |
|---|---|---|
| partner | a manufacturing partner, by id | `edge-labs` |
| organization | the partner's name in O= on its device certificates and intermediate CSRs. Required for every partner environment | `EDGE Labs` |
| stage | which gateway the certificates are for | `dev`, `prod` |
| environment | one partner's stage on a signer, `<partner>-<stage>`; its own intermediate (KMS key) and permissions. Users never type it | `edge-labs-prod` |
| device id | the certificate CN: the partner's prefix + the board's MAC, the same in every stage | `DVTADL3C71BF4A12E0` |
| serial | the certificate's X.509 serial number, never the device id | `1BA770E3...` |
| chip_id | the board's MAC in the API (`adl --mac`, or read with `--port`) | `3c71bf4a12e0` |

```json
[
  {"name": "edge-labs-prod", "partner": "edge-labs", "stage": "prod", "organization": "EDGE Labs",
   "kms_key_id": "...", "device_prefix": "DVTADL", "device_id_from_chip": true, "validity_days": 3650}
]
```

`device_id_from_chip` implies `require_chip_id`. There is no counter: a
board gets the same device id from the dev and the prod signer without them
sharing anything. Within one signer a device id belongs to one environment.
All stages of a partner must share the prefix and id scheme, and partners'
prefixes must not overlap; the server refuses to start otherwise.

## Who acts for which partner

Bindings in `ADL_AUTH_POLICY` take `accounts`, the accounts whose
identities the binding matches (the top-level `accounts` is who may call at
all). Name and role patterns are only unique within an account, so with
more than one account scope every binding:

```json
{"accounts": ["111111111111", "222222222222"],
 "bindings": [
   {"accounts": ["111111111111"], "roles": ["AWSReservedSSO_AdministratorAccess_*"], "permissions": ["*"]},
   {"accounts": ["111111111111"], "users": ["edge-labs"],
    "permissions": ["edge-labs-prod:issue", "edge-labs-prod:read", "edge-labs-prod:provision", "edge-labs-prod:revoke"]},
   {"accounts": ["222222222222"], "roles": ["*"], "users": ["*"], "permissions": ["acme-prod:issue", "acme-prod:read"]}
 ]}
```

`ca:admin` (intermediate CSR and install), `admin:import` and `audit:read`
are global: keep them for the operator's own staff.

## The CLI

`/v1/whoami` lists the environments the caller may use, with their partner,
stage and actions (a permission without its environment: `issue`, `read`,
...). `--stage` takes a stage: a partner's people land in their own
environment; people who may act for several partners add `--partner <id>`
or set a default with `adl configure --partner <id>`. `--env` is the older
spelling of `--stage`.

With a signer per stage, configure both; `--stage` also picks the server:

```bash
adl configure --stage dev  --url https://signer.dev.autorq.com  --region us-east-1 --audience autorq-signer:dev  --profile edge-labs-dev
adl configure --stage prod --url https://signer.prod.autorq.com --region us-east-1 --audience autorq-signer:prod --profile edge-labs-prod
adl whoami --stage dev
adl mint --stage dev --port /dev/ttyUSB0                   # MAC read with esptool
adl eol provision --stage prod --station line-1 --port /dev/ttyUSB0
adl show DVTADL3C71BF4A12E0 --stage prod
adl mint --partner acme --stage dev --mac 00:11:22:33:44:55   # AutorQ staff
adl ca csr --partner acme --stage prod --cn "ACME Intermediate CA prod"   # O=ACME by default
```

`/healthz` no longer lists environments, so anonymous callers can't
enumerate partners.
