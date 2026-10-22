# End-of-line provisioning (ESP32-S3)

This is the factory step that gives a production board its identity. The
identity goes into the board's `adl_certs` NVS partition, the same place
`adl flash` puts it on a dev board. No eFuses are burned.

Boards must already run firmware whose partition table has `adl_certs`
(see [firmware-nvs.md](firmware-nvs.md)).

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
4. Writes key and certs to a private tmpfs dir (`/dev/shm/adl-flash-*`,
   mode 0700). Reads the partition table off the board, builds an NVS image
   for `adl_certs` with Espressif's `nvs_partition_gen` and writes it with
   esptool. Then runs the optional verify script.
5. Wipes the tmpfs dir. The key now exists only on the board.
6. Confirms back to the server with the serial it flashed. The device
   moves from `issued` to `provisioned`, stamped with station, firmware
   version and time.
7. Prints a big PASS/FAIL and appends a line to the station's CSV log
   (`~/.local/state/adl/eol-log.csv`).

### Failures and re-runs

| situation | what to do | what happens |
|---|---|---|
| flash/verify fails, cable pulled, power cut | fix it, run again on the same board | server sees the chip already has an *unconfirmed* identity and re-keys that same identity. The previous cert is revoked as superseded. Same device ID |
| board was already provisioned and comes back down the line | stop, find out why | refused with "already provisioned as GLXADL0xx" |
| re-keying a shipped or returned board on purpose | a CA admin runs with `--reissue` | needs `prod:revoke`, which stations don't have |
| "has no adl_certs partition" | flash firmware with the current partition table, re-run | nothing was written; the board keeps its unconfirmed identity for the re-run |
| server unreachable | check network/creds, re-run | nothing was written to the board yet |

## Station setup

`adl eol --help` prints this whole page in short form (setup, a shift, what
happens per board, what to do on FAIL), and `adl eol provision --help` has
every flag plus the flash script contract. Point operators there first.

### Hardware/software

- Linux PC (any distro with `/dev/shm`) with USB to the fixture.
- Python with Espressif's `esptool` and `esp-idf-nvs-partition-gen`,
  pinned to tested versions:
  ```sh
  pip install esptool==<ver> esp-idf-nvs-partition-gen==<ver>
  ```
  A machine with ESP-IDF installed already has both in the IDF Python
  environment. Point adl at it with
  `export ADL_NVS_GEN="$IDF_PYTHON_ENV_PATH/bin/python -m esp_idf_nvs_partition_gen"`.
- The `adl` binary from `make cli`:
  ```sh
  ./adl-linux-amd64 install                # ~/.local/bin/adl + completion
  ```
  For a shared station login use `sudo ./adl-linux-amd64 install system`.

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
installed, and that esptool and the NVS generator run.

### Running a shift

```sh
adl eol provision --port /dev/ttyUSB0 --firmware 1.4.2 --loop
```

`--loop` waits for Enter between boards.

## What gets written

Namespace `adl` in the `adl_certs` partition: `device_id`, `device_cert`,
`device_chain`, `device_key` and `ca_root`, all PEM strings. The details,
the partition table line and the C code that reads them are in
[firmware-nvs.md](firmware-nvs.md). `--nvs-template` changes the layout and
`--nvs-partition` the target partition. adl will never write `nvs_cc`
(cc_comm's own partition), and only writes partitions that are data/nvs in
the table it reads off the board.

The key is plaintext in that partition. See "Protecting the key" in
firmware-nvs.md for what flash and NVS encryption would change.

### Custom flash scripts and the eFuse option

`--flash-script` (or `ADL_FLASH_SCRIPT`) replaces the NVS step with your own
script. It gets these environment variables and must exit 0 only if the
board is good:

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

`scripts/eol/flash-esp-secure-cert-ds.sh` is one such script, kept for
firmware that wants the ESP32-S3 Digital Signature peripheral. It burns an
HMAC key into an eFuse block so the plaintext key never sits in flash.
That's permanent, so the script refuses to run unless `ADL_BURN_EFUSE=yes`
and `ADL_SECURE_CERT_OFFSET` are set. It uses Espressif's
`configure_esp_secure_cert.py`, which Espressif documents as a development
tool, and the ADL firmware doesn't use `esp_secure_cert_mgr` today. Treat it
as a reference, not the production path.

`--verify-script` (see `scripts/eol/verify-example.sh`) runs after the flash
with the same variables. The best verify is "board boots and completes a TLS
handshake to the cloud with its new cert".

## Recommended line hardening (firmware side, outside this repo)

These aren't done by the signer, but a production line should have them:

- Secure Boot v2 enabled and the key digest burned, so only signed
  firmware runs.
- Flash encryption in release mode, with NVS encryption for `adl_certs`
  (needs a matching change to the flash step; see firmware-nvs.md).
- JTAG and the UART download mode locked down after provisioning
  (`DIS_PAD_JTAG`, `DIS_DOWNLOAD_MODE` / secure download mode), as the
  product allows.

Do these after the identity step, and in a fixed order that's been tried on
scrap boards. Several of them are one-way.
