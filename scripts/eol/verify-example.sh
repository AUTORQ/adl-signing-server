#!/usr/bin/env bash
# Example post-flash check for `adl eol provision --verify-script`.
#
# Resets the board and waits for the firmware to print its identity on the
# console. Adapt the expected line to whatever the firmware logs once it has
# loaded the certificate (ideally after a successful TLS handshake with the
# cloud endpoint using that certificate).
set -euo pipefail
: "${ADL_PORT:?}" "${ADL_DEVICE_ID:?}"

EXPECT="${ADL_VERIFY_EXPECT:-device id: ${ADL_DEVICE_ID}}"
TIMEOUT="${ADL_VERIFY_TIMEOUT:-45}"

"${ADL_ESPTOOL:-esptool.py}" --chip "${ADL_CHIP:-esp32s3}" --port "${ADL_PORT}" --after hard_reset chip_id >/dev/null

stty -F "${ADL_PORT}" 115200 raw -echo
if timeout "${TIMEOUT}" grep -m1 -F "${EXPECT}" < "${ADL_PORT}"; then
  echo "device reported expected identity"
else
  echo "did not see '${EXPECT}' within ${TIMEOUT}s" >&2
  exit 1
fi
