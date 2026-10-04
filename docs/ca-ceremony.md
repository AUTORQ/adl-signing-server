# CA ceremony, rotation and migrating off the droplet

## How the hierarchy looks

```
AutorQ Root CA            offline, held by AutorQ, never touches this system
  |-- EDGE Labs Intermediate CA dev    private key = KMS key alias/adl-signer-ca-dev
  |     `-- DVTADL### dev device certs
  `-- EDGE Labs Intermediate CA prod   private key = KMS key alias/adl-signer-ca-prod
        `-- DVTADL### prod device certs
```

Each environment's intermediate private key is created inside KMS by
Terraform and can't be exported. The ceremony gets the root to sign a
certificate for that KMS key.

Today the only root in use is `AutorQ Root CA dev` (RSA-4096), and both of
the droplet's intermediates chain to it. If AutorQ creates a separate prod
root, use it for the prod ceremony below. Nothing else changes.

## First-time setup (per environment)

You need `ca:admin` (the `adl-ca-admin` role, or a binding with `*`).

### 1. Get a CSR out of KMS

```sh
adl ca csr --env prod --cn "EDGE Labs Intermediate CA prod" \
           --org "EDGE Labs" --ou "IoT Devices" --country US \
           --out prod-intermediate.csr
```

### 2. The root holder signs it

Do this on the offline machine that holds the root key. Use an extension
file so the result is a proper pathlen-0 intermediate:

```sh
cat > intermediate.ext <<'EOF'
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

openssl req -in prod-intermediate.csr -noout -verify -subject   # sanity check
openssl x509 -req -in prod-intermediate.csr \
  -CA autorq-root.pem -CAkey autorq-root.key -CAcreateserial \
  -days 7300 -sha384 -extfile intermediate.ext \
  -out prod-intermediate.pem
cat prod-intermediate.pem autorq-root.pem > prod-chain.pem
```

20 years (`-days 7300`) matches the droplet intermediates. Device certs are
clamped so they never outlive their intermediate.

### 3. Install it

```sh
adl ca install --env prod --chain prod-chain.pem
adl ca status  --env prod
```

The server refuses the chain unless the intermediate's public key matches
the KMS key, it's a CA with keyCertSign, it's currently valid, and it
chains to the self-signed root at the end of the file. The chain is stored
at `s3://<archive>/ca/prod/chain.pem`, with a copy under
`ca/prod/history/<fingerprint>.pem`, and an initial CRL is published.

Do the same for `dev`. Until an environment's CA is installed, issuing for it
fails with `ca_not_configured`.

### 4. Publish the trust info

- The cloud side (whatever authenticates devices, e.g. AWS IoT Core CA
  registration or an mTLS trust store) needs the new intermediates, or
  just the root if it trusts by root.
- The CRL for each environment is public at `GET /v1/ca/<env>/crl` (DER),
  and the chain at `GET /v1/ca/<env>/chain.pem`.

## Rotating an intermediate

Rotate before the intermediate expires (`adl ca status` warns inside a year),
or right away if you believe a key is compromised.

1. In Terraform, rotating means a new KMS key: add an environment such as
   `prod2` with the same settings, or replace the key resource. The CA
   keys are `prevent_destroy`, so the old one can't vanish by accident.
2. Run the ceremony for the new key.
3. Make sure the cloud trusts the new intermediate before any device
   carries a cert from it.
4. Old devices keep working until their certs expire or are re-issued.
   CRLs are per issuer: the server only puts certs on a CRL if that CRL's
   issuer signed them.

## Migrating off the droplet

The droplet (`autorq-key-signing-server`) has both intermediate private keys,
and every device key it ever generated, sitting as plain files under `/root`
on an internet-facing host. **Treat both droplet intermediates as possibly
compromised.** The plan:

Step 1: stand this system up and run the ceremony for dev and prod (above),
with new KMS-backed intermediates. From then on, all new certs come from
here.

Step 2: import the existing devices so they show up in the registry and the
counter carries on from DVTADL016. Copy the directories off the droplet over
SSH to an admin machine first, never via a third party:

```sh
# dev: certs and keys, so developers can `adl fetch` the old boards
adl import --env dev  --dir ./droplet-copy/dev-keys/device --with-keys --dry-run
adl import --env dev  --dir ./droplet-copy/dev-keys/device --with-keys

# prod: certificates only; prod keys are never escrowed
adl import --env prod --dir ./droplet-copy/prod-keys/device --provisioned
```

Imports are idempotent (re-running skips what's already there). They record
the legacy chain alongside each cert. The registry can't know which chip
each legacy board is, so those devices have no chip binding.

Going by the droplet's shell history, `prod-keys/` was cloned from
`dev-keys/`, so `prod-keys/device/` also holds DVTADL001-006. Import dev
first. Those six are then skipped as already registered (same serials)
instead of showing up as prod devices. Check `adl show` on a couple of
them afterwards.

Step 3: decide with AutorQ what to do with the legacy intermediates.
Options, strongest first:

- Have the root holder revoke both droplet intermediates on the root's CRL,
  and re-provision the legacy prod devices with
  `adl eol provision --reissue` the next time they're in hand
  (`adl list --env prod` after the import is the list). This is the
  clean answer if anything else ever lived on that box or its SSH key was
  shared.
- If the boards can't be recalled, keep trusting the legacy prod
  intermediate for those serials only, and plan the re-key into the next
  firmware update.

Step 4: destroy the droplet's key material once the copies are verified:
shred the `prod-keys/` and `dev-keys/` trees and the zips, then destroy
the droplet (and its snapshots/backups in DigitalOcean). Remove the root
SSH key it accepted from anywhere else it is trusted.

## Revocation

```sh
adl revoke DVTADL023 --reason keyCompromise          # all active certs on the device
adl revoke DVTADL023 --reason superseded --serial 5E757B55...
```

Reasons: `keyCompromise`, `superseded`, `cessationOfOperation`,
`affiliationChanged`, `unspecified`. The environment's CRL is re-signed
immediately and otherwise refreshed at half its lifetime (7 days by default).
