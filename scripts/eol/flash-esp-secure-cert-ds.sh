#!/usr/bin/env bash
# OPTIONAL, NOT THE DEFAULT. This burns an eFuse.
#
# adl writes the identity into the adl_certs NVS partition by default and
# burns nothing. This script is the alternative for firmware that uses the
# ESP32-S3 Digital Signature (DS) peripheral through esp_secure_cert_mgr:
# the private key is encrypted with an HMAC key that is burned into an
# eFuse key block, so the plaintext key never sits in flash.
#
# Things to know before using it:
#   - Burning an eFuse is permanent. Try the whole flow on scrap boards.
#   - Espressif documents configure_esp_secure_cert.py as a development
#     tool ("This tool is to be used only for development purpose"). For a
#     production line, build the esp_secure_cert partition with their
#     manufacturing tooling and keep this as a reference.
#   - The firmware must use esp_secure_cert_mgr and have an esp_secure_cert
#     partition. The tool's default offset (0xD000) is inside the ADL
#     board's nvs partition (0x9000-0xF000), so ADL_SECURE_CERT_OFFSET must
#     be set to where that partition really is.
#
# Use it with:
#   ADL_BURN_EFUSE=yes ADL_SECURE_CERT_OFFSET=0x... \
#     adl eol provision --flash-script /path/to/flash-esp-secure-cert-ds.sh ...
#
# adl sets ADL_PORT ADL_CHIP ADL_DEVICE_ID ADL_SERIAL ADL_DEVICE_KEY
# ADL_DEVICE_CERT ADL_CA_ROOT ADL_WORK_DIR (see docs/eol-provisioning.md).
set -euo pipefail

: "${ADL_PORT:?}" "${ADL_DEVICE_KEY:?}" "${ADL_DEVICE_CERT:?}" "${ADL_CA_ROOT:?}" "${ADL_WORK_DIR:?}"

if [[ "${ADL_BURN_EFUSE:-}" != "yes" ]]; then
  echo "refusing: this script burns an eFuse key block. Set ADL_BURN_EFUSE=yes to allow it." >&2
  exit 2
fi
if [[ -z "${ADL_SECURE_CERT_OFFSET:-}" ]]; then
  echo "refusing: set ADL_SECURE_CERT_OFFSET to the esp_secure_cert partition offset in your partition table." >&2
  exit 2
fi

TOOL="${ADL_SECURE_CERT_TOOL:-configure_esp_secure_cert.py}"
EFUSE_KEY_ID="${ADL_EFUSE_KEY_ID:-1}"

echo "flashing ${ADL_DEVICE_ID} (serial ${ADL_SERIAL}) to ${ADL_PORT}, DS key in eFuse block ${EFUSE_KEY_ID}"

# The tool drops intermediate files in the current directory, so run it
# inside the tmpfs work dir that adl wipes afterwards.
cd "${ADL_WORK_DIR}"

# shellcheck disable=SC2086
"${TOOL}" \
  -p "${ADL_PORT}" \
  --target_chip "${ADL_CHIP:-esp32s3}" \
  --private-key "${ADL_DEVICE_KEY}" \
  --device-cert "${ADL_DEVICE_CERT}" \
  --ca-cert "${ADL_CA_ROOT}" \
  --sec_cert_type cust_flash_tlv \
  --sec_cert_part_offset "${ADL_SECURE_CERT_OFFSET}" \
  --configure_ds --efuse_key_id "${EFUSE_KEY_ID}" \
  ${ADL_SECURE_CERT_EXTRA_ARGS:-}

echo "flash complete for ${ADL_DEVICE_ID}"
