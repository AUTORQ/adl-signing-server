#!/usr/bin/env bash
# Writes the device identity onto an ESP32-S3 at end of line.
#
# Called by `adl eol provision`, which sets:
#   ADL_PORT ADL_CHIP ADL_ESPTOOL ADL_DEVICE_ID ADL_SERIAL ADL_CHIP_MAC ADL_ENV
#   ADL_DEVICE_KEY ADL_DEVICE_CERT ADL_DEVICE_CHAIN ADL_CA_CHAIN ADL_CA_ROOT ADL_WORK_DIR
# The key files live in a tmpfs dir that adl wipes as soon as this returns.
#
# Default path: Espressif's esp_secure_cert tooling. The private key is
# encrypted for the Digital Signature (DS) peripheral using an HMAC key
# burned into an eFuse block, so the plaintext key never sits in flash and
# firmware can only *use* it through the DS peripheral. The S3's DS
# peripheral is RSA only, which is why stations default to RSA-2048 keys.
#
# BURNING AN EFUSE IS PERMANENT. Try this on scrap boards first, and pin the
# esp-secure-cert-tool version on the station:
#   pip install esp-secure-cert-tool==<pinned version>
# Check the flags against `configure_esp_secure_cert.py --help` for that
# version, they have moved around between releases.
#
# If the firmware reads its credentials some other way (NVS, a raw partition)
# replace this script; adl only cares that it exits 0 on success.
set -euo pipefail

: "${ADL_PORT:?}" "${ADL_DEVICE_KEY:?}" "${ADL_DEVICE_CERT:?}" "${ADL_CA_ROOT:?}" "${ADL_WORK_DIR:?}"

TOOL="${ADL_SECURE_CERT_TOOL:-configure_esp_secure_cert.py}"
EFUSE_KEY_ID="${ADL_EFUSE_KEY_ID:-1}"
# Set ADL_SECURE_CERT_SKIP_DS=1 on boards/firmware that keep the key in an
# encrypted partition instead of using the DS peripheral.
DS_ARGS=(--configure_ds --efuse_key_id "${EFUSE_KEY_ID}")
if [[ "${ADL_SECURE_CERT_SKIP_DS:-0}" == "1" ]]; then
  DS_ARGS=()
fi

echo "flashing ${ADL_DEVICE_ID} (serial ${ADL_SERIAL}) to ${ADL_PORT}"

# The tool drops intermediate files (and, without --keep_ds_data_on_host,
# nothing sensitive) in the current directory, so run it inside the tmpfs.
cd "${ADL_WORK_DIR}"

# shellcheck disable=SC2086
"${TOOL}" \
  -p "${ADL_PORT}" \
  --target_chip "${ADL_CHIP:-esp32s3}" \
  --private-key "${ADL_DEVICE_KEY}" \
  --device-cert "${ADL_DEVICE_CERT}" \
  --ca-cert "${ADL_CA_ROOT}" \
  --sec_cert_type cust_flash_tlv \
  "${DS_ARGS[@]}" \
  ${ADL_SECURE_CERT_EXTRA_ARGS:-}

echo "flash complete for ${ADL_DEVICE_ID}"
