# CA ceremony, rotation and importing existing certificates

## How the hierarchy looks

```
Root CA                          offline, held by you, never touches this system
  |-- Globex Intermediate CA dev    private key = KMS key alias/adl-signer-ca-dev
  |     `-- GLXADL### dev device certs
  `-- Globex Intermediate CA prod   private key = KMS key alias/adl-signer-ca-prod
        `-- GLXADL### prod device certs
```

Each environment's intermediate private key is created inside KMS by
Terraform and can't be exported. The ceremony gets the root to sign a
certificate for that KMS key.

One root can sign both intermediates, or you can keep a separate prod root
and use it for the prod ceremony below. Nothing else changes.

## First-time setup (per environment)

You need `ca:admin` (the `adl-ca-admin` role, or a binding with `*`).

### 1. Get a CSR out of KMS

```sh
adl ca csr --stage prod --cn "Globex Intermediate CA prod" \
           --org "Globex" --ou "IoT Devices" --country US \
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
  -CA root.pem -CAkey root.key -CAcreateserial \
  -days 7300 -sha384 -extfile intermediate.ext \
  -out prod-intermediate.pem
cat prod-intermediate.pem root.pem > prod-chain.pem
```

20 years (`-days 7300`) is a common lifetime for an intermediate. Device
certs are clamped so they never outlive their intermediate.

### 3. Install it

```sh
adl ca install --stage prod --chain prod-chain.pem
adl ca status  --stage prod
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
  and the chain at `GET /v1/ca/<env>/chain.pem`. `adl ca pull --stage prod`
  writes the root, intermediate and chain as separate files.

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

## Importing existing certificates

If devices already carry certificates from an earlier CA setup (openssl
scripts, another signer), import them so they show up in the registry and,
with a counter, so new IDs carry on after the highest one imported. Copy the
certificate directories to an admin machine first, over SSH, never via a
third party. `adl import` reads every `device-<ID>.crt` under `--dir`:

```sh
# dev: certs and keys, so developers can `adl fetch` the old boards
adl import --stage dev  --dir ./old-ca/dev/device --with-keys --dry-run
adl import --stage dev  --dir ./old-ca/dev/device --with-keys

# prod: certificates only; prod keys are never escrowed
adl import --stage prod --dir ./old-ca/prod/device --provisioned
```

You need `admin:import`. Imports are idempotent (re-running skips what's
already there, by serial) and record the legacy chain alongside each cert.
The registry can't know which chip each legacy board is, so imported devices
have no chip binding. If the same certificates sit in both trees, import dev
first; the duplicates are then skipped instead of showing up as prod devices.

If the old intermediate keys ever lived as files on a networked host, treat
them as compromised:

- Have the root holder revoke the old intermediates on the root's CRL, and
  re-provision the legacy prod devices with `adl eol provision --reissue`
  the next time they're in hand (`adl list --stage prod` after the import is
  the list).
- If the boards can't be recalled, keep trusting the old prod intermediate
  for those serials only, and plan the re-key into the next firmware update.

Once the copies are verified, destroy the old key material and the host's
snapshots and backups.

## Revocation

```sh
adl revoke GLXADL023 --reason keyCompromise          # all active certs on the device
adl revoke GLXADL023 --reason superseded --serial 5E757B55...
```

Reasons: `keyCompromise`, `superseded`, `cessationOfOperation`,
`affiliationChanged`, `unspecified`. The environment's CRL is re-signed
immediately and otherwise refreshed at half its lifetime (7 days by default).
