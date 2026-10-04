# Developer guide

You need a certificate for a dev board. This takes about a minute the first
time and a few seconds after that.

## One-time setup

1. Get the `adl` binary for your machine from the latest build (`make cli`
   output, or ask whoever runs releases) and put it on your `PATH`.
2. Make sure you can get AWS credentials for the account the signer runs in.
   Normally that's IAM Identity Center:
   ```sh
   aws configure sso            # once
   aws sso login --profile autorq-dev
   ```
   Your SSO permission set (or the `adl-developer` role) needs to be bound to
   the dev permissions on the server. If `adl whoami` says forbidden, ask a
   CA admin to add you.
3. Point the CLI at the server. The values are Terraform outputs
   (`cli_configure`):
   ```sh
   adl configure --url https://signer.example \
                 --region us-east-1 \
                 --audience adl-signing-server:123456789012 \
                 --profile autorq-dev
   adl whoami
   ```

The config lives in `~/.config/adl/config.json`. `ADL_URL`, `ADL_REGION`,
`ADL_AUDIENCE` and `ADL_PROFILE` override it.

## Minting a certificate

```sh
adl mint
```

You get the next free device ID and these files:

```
certs/DVTADL017/device/device-DVTADL017.crt         the device certificate
certs/DVTADL017/device/device-DVTADL017.key         its private key (0600)
certs/DVTADL017/device/device-DVTADL017-chain.pem   cert + intermediate (same as the old bundles)
certs/DVTADL017/device/ca-chain.pem                 intermediate + root
certs/DVTADL017/bundle.json                         id / env / serial
```

That's the same layout the old droplet zips had, so existing flashing
scripts keep working. Useful flags:

| flag | what |
|---|---|
| `--label board=rev-c` | tag the device (repeatable); shows up in `adl show` |
| `--out DIR` | where to write (default `./certs`) |
| `--zip` | also write `DVTADL017.zip` |
| `--id BENCH-JIG-01` | a custom ID outside the DVTADL range (DVTADL numbers are always allocated) |
| `--replace --id DVTADL017` | re-key an existing device. The old cert is revoked as superseded |
| `--no-escrow` | don't back the key up on the server |
| `--key-type ecdsa-p256` | ECDSA instead of RSA-2048 (only if your firmware doesn't use the DS peripheral) |

## Lost it?

```sh
adl fetch DVTADL017
```

This brings back the cert, chain and private key exactly as issued. It works
because dev keys are escrowed (encrypted with a dedicated KMS key, readable
only by the service). Every fetch that includes a key is written to the audit
log. Use `--no-key` if you only need the public parts.

## Looking around

```sh
adl list                 # every dev device you can see
adl show DVTADL017       # status, labels, every cert it has had
```

## Things to know

- Dev certificates chain to the dev intermediate, not the prod one, so the
  cloud side can (and should) refuse dev identities in production.
- Escrow is a convenience for dev hardware only. Prod keys are never sent
  to the server.
- Don't commit the `certs/` directory into your firmware repo. Add it to
  that repo's `.gitignore`.
- If a dev key leaks (pasted in Slack, pushed to GitHub), tell a CA admin.
  They'll run `adl revoke DVTADL017 --reason keyCompromise` and you mint a
  new one.
