# Developer guide

You need a certificate for a dev board. This takes about a minute the first
time and a few seconds after that.

## One-time setup

1. Install `adl` and its tab completion:
   ```sh
   go install github.com/AUTORQ/adl-signing-server/cmd/adl@latest   # lands in $(go env GOPATH)/bin
   adl install completion
   ```
   Or take the binary for your machine from `make cli` and let it install
   itself: `./adl-linux-amd64 install` (`~/.local/bin/adl` plus completion),
   or `sudo ./adl-linux-amd64 install system` machine-wide. Use
   `adl install cli local|system` or `adl install completion local|system`
   for just one half, and `--shell zsh` if `$SHELL` guesses wrong. Open a
   new shell afterwards and tab completion works for commands, flags,
   stages, partners, device IDs and serials.
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

The config lives in `adl/config.json` under your user config directory
(`~/.config` on Linux, `~/Library/Application Support` on macOS,
`%AppData%` on Windows); `ADL_CONFIG` points it elsewhere. `ADL_URL`,
`ADL_REGION`, `ADL_AUDIENCE`, `ADL_PROFILE` and `ADL_PARTNER` override it.
With one signer per stage, configure each with `--stage dev|prod`
(see [partners.md](partners.md)).

## Minting a certificate

```sh
adl mint
```

You get the next free device ID (or, if the environment makes IDs from the
chip, pass `--mac 3c:71:bf:4a:12:e0` or `--port /dev/ttyUSB0` to read it with
esptool) and these files:

```
certs/GLXADL017/device/device-GLXADL017.crt         the device certificate
certs/GLXADL017/device/device-GLXADL017.key         its private key (0600)
certs/GLXADL017/device/device-GLXADL017-chain.pem   cert + intermediate
certs/GLXADL017/device/ca-chain.pem                 intermediate + root
certs/GLXADL017/device/ca-root.pem                  root CA on its own
certs/GLXADL017/bundle.json                         id / env / serial
```

Useful flags:

| flag | what |
|---|---|
| `--stage prod` | another stage (default `dev`) |
| `--label board=rev-c` | tag the device (repeatable); shows up in `adl show` |
| `--out DIR` | where to write (default `./certs`) |
| `--zip` | also write `GLXADL017.zip` |
| `--id BENCH-JIG-01` | a custom ID outside the GLXADL range (GLXADL numbers are always allocated) |
| `--replace --id GLXADL017` | re-key an existing device. The old cert is revoked as superseded |
| `--no-escrow` | don't back the key up on the server |
| `--key-type ecdsa-p256` | ECDSA instead of RSA-2048 (only if your firmware doesn't use the DS peripheral) |

## Flashing it onto a board

```sh
adl mint --port /dev/ttyUSB0        # mint and flash in one go
adl flash GLXADL017 --port /dev/ttyUSB0
```

This writes the cert, chain, key and root CA into the board's `adl_certs`
NVS partition. No eFuses are burned, and it doesn't touch the `nvs`
partition (your Wi-Fi settings) or cc_comm's `nvs_cc`. The board has to
run firmware with the `adl_certs` partition; see
[firmware-nvs.md](firmware-nvs.md). If it doesn't, adl says so and writes
nothing. The first time, follow "Bringing up the first board" in that page.

`adl flash` uses the files in `certs/GLXADL017/`. If they're gone it pulls
them from the server first.

You need esptool and Espressif's NVS generator. If you have ESP-IDF
installed, both are already in its Python environment:

```sh
export ADL_NVS_GEN="$IDF_PYTHON_ENV_PATH/bin/python -m esp_idf_nvs_partition_gen"
export ADL_ESPTOOL=esptool.py      # from the IDF environment (. ./export.sh)
```

Otherwise `pip install esptool esp-idf-nvs-partition-gen` and the defaults
work.

## Lost it?

```sh
adl fetch GLXADL017
```

This brings back the cert, chain, root CA and private key exactly as
issued. It works because dev keys are escrowed (encrypted with a dedicated
KMS key, readable only by the service). Every fetch that includes a key is written to the audit
log. Use `--no-key` if you only need the public parts.

If you only need the CA certificates (for a firmware build or a trust
store), you don't need a device at all:

```sh
adl ca pull --stage dev                # <env>-root.pem, <env>-intermediate.pem, <env>-ca-chain.pem
```

The CA private keys live in KMS and can't be downloaded by anyone. That's
on purpose.

## Looking around

```sh
adl list                 # every dev device you can see
adl show GLXADL017       # status, labels, every cert it has had
```

## Things to know

- Dev certificates chain to the dev intermediate, not the prod one, so the
  cloud side can (and should) refuse dev identities in production.
- Escrow is a convenience for dev hardware only. Prod keys are never sent
  to the server.
- Don't commit the `certs/` directory into your firmware repo. Add it to
  that repo's `.gitignore`.
- If a dev key leaks (pasted in Slack, pushed to GitHub), tell a CA admin.
  They'll run `adl revoke GLXADL017 --reason keyCompromise` and you mint a
  new one.
