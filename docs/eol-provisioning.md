# End-of-line provisioning (ESP32-S3)

This is the factory step that gives a production board its identity.

## What happens per board

`adl eol provision` does this for each board on the fixture:

1. Reads the chip's factory MAC with `esptool read_mac`. The MAC is the
   chip's permanent ID in the registry, and one chip can only ever hold one
   device identity.
2. Generates an RSA-2048 key on the station, in memory.
3. Sends only the CSR and MAC to the signer. The server allocates the
   device ID (the next number, `GLXADL0xx`, or prefix + MAC if the
   environment makes IDs from the chip), signs with the prod CA key in KMS and records
   the chip binding. The prod environment refuses to escrow keys and refuses
   certs without a chip ID.
4. Writes key and certs to a private tmpfs dir (`/dev/shm/adl-eol-*`,
   mode 0700) and runs the flash script, then the optional verify
   script.
5. Wipes the tmpfs dir. The key now exists only on the chip.
6. Confirms back to the server with the serial it flashed. The device
   moves from `issued` to `provisioned`, stamped with station, firmware
   version and time.
7. Prints a big PASS/FAIL and appends a line to the station's CSV log
   (`~/.local/state/adl/eol-log.csv`).

### Failures and re-runs

| situation | what to do | what happens |
|---|---|---|
| flash/verify script fails, cable pulled, power cut | fix it, run again on the same board | server sees the chip already has an *unconfirmed* identity and re-keys that same identity. The previous cert is revoked as superseded. Same device ID |
| board was already provisioned and comes back down the line | stop, find out why | refused with "already provisioned as GLXADL0xx" |
| re-keying a shipped or returned board on purpose | a CA admin runs with `--reissue` | needs `prod:revoke`, which stations don't have |
| server unreachable | check network/creds, re-run | nothing was written to the board yet |

## Station setup

### Hardware/software

- Linux PC (any distro with `/dev/shm`) with USB to the fixture.
- Python + `esptool` and `esp-secure-cert-tool`, pinned to tested versions:
  ```sh
  pip install esptool==<ver> esp-secure-cert-tool==<ver>
  ```
- `adl` binary plus `flash-esp32s3.sh` (and your verify script) from
  `make cli`. Keep them side by side, or set `ADL_FLASH_SCRIPT`.

### Credentials

The station needs AWS credentials that resolve to a role bound to
`prod:issue`, `prod:provision` and `prod:read`. The `adl-factory-station`
role (Terraform `create_client_roles = true`) is exactly that. Options,
best first:

1. IAM Roles Anywhere. The station holds an X.509 cert (ideally in a TPM)
   and swaps it for short-lived `adl-factory-station` credentials through
   `credential_process` in `~/.aws/config`. There's no long-lived secret on
   the PC, and revoking the station cert cuts it off. Put the trust anchor
   ARN in `factory_station_trust_anchor_arns`.
2. IAM Identity Center. Operators sign in at the start of a shift with a
   permission set bound to the station permissions. That gives a per-person
   audit trail, but needs a browser login each day.
3. Not long-lived IAM user keys on the station PC.

Then, once per station:

```sh
adl configure --url https://signer.example --region us-east-1 \
              --audience adl-signing-server:123456789012 --profile factory
export ADL_STATION=line-1          # recorded on every board
adl eol check
```

`adl eol check` confirms the identity, permissions, that the prod CA is
installed, and that esptool and the flash script are present.

### Running a shift

```sh
adl eol provision --port /dev/ttyUSB0 --firmware 1.4.2 --loop
```

`--loop` waits for Enter between boards.

## The flash script

`scripts/eol/flash-esp32s3.sh` is the default. It uses Espressif's
`configure_esp_secure_cert.py` to:

- encrypt the device private key for the S3's Digital Signature (DS)
  peripheral with an HMAC key it burns into an eFuse block, and
- write the cert, CA and encrypted key into the `esp_secure_cert` partition.

With DS the plaintext key never lands in flash. Firmware can only *use* it
through the peripheral (the `esp_secure_cert_mgr` component), so a
flash dump doesn't leak it. The S3 DS peripheral only does RSA, which is why
device keys are RSA-2048. That also matches every cert issued so far.

> **eFuse burns are permanent.** Validate the whole line flow on scrap
> boards first. Check the script's flags against
> `configure_esp_secure_cert.py --help` for the version you pinned, since
> they have changed between releases. The firmware has to be built with
> `esp_secure_cert_mgr` and the matching partition table, or it won't find
> the credentials.

If the firmware reads credentials some other way (NVS, a raw partition,
flash-encrypted SPIFFS), replace the script. The contract is simple: the
script gets these environment variables and must exit 0 only if the board is
good:

| variable | contents |
|---|---|
| `ADL_PORT`, `ADL_CHIP`, `ADL_ESPTOOL` | where and how to talk to the board |
| `ADL_DEVICE_ID`, `ADL_SERIAL`, `ADL_CHIP_MAC`, `ADL_ENV` | identity being written |
| `ADL_KEY_ALGORITHM` | key type of the device key (RSA by default) |
| `ADL_DEVICE_KEY` | path to the PEM private key (PKCS#8) |
| `ADL_DEVICE_CERT` | path to the device certificate |
| `ADL_DEVICE_CHAIN` | path to device cert + intermediate |
| `ADL_CA_CHAIN` | path to intermediate + root |
| `ADL_CA_ROOT` | path to the root only |
| `ADL_WORK_DIR` | the tmpfs dir (wiped afterwards) |

`--verify-script` (see `scripts/eol/verify-example.sh`) runs after the flash
with the same variables. The best verify is "board boots and completes a TLS
handshake to the cloud with its new cert".

## Recommended line hardening (firmware side, outside this repo)

These aren't done by the signer, but a production line should have them:

- Secure Boot v2 enabled and the key digest burned, so only signed
  firmware runs.
- Flash encryption in release mode.
- JTAG and the UART download mode locked down after provisioning
  (`DIS_PAD_JTAG`, `DIS_DOWNLOAD_MODE` / secure download mode), as the
  product allows.

Do these after the identity step, and in a fixed order that's been tried on
scrap boards. Several of them are one-way.
