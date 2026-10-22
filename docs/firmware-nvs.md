# Device identity in NVS (firmware side)

`adl flash`, `adl mint --port` and `adl eol provision` all write the device
identity into an NVS partition called `adl_certs`. This page is what the
firmware needs to do to have that partition and read it.

No eFuses are burned anywhere in this flow.

## 1. Add the partition

Add one line to the end of `cc_partitions.csv`:

```
# Name,   Type, SubType, Offset,  Size, Flags
nvs,      data, nvs,     ,        0x6000,
nvs_cc,   data, nvs,     ,        0x6000,
phy_init, data, phy,     ,        0x1000,
factory,  app,  factory, ,        1M,
adl_certs,data, nvs,     ,        0x6000,
```

Putting it last means nothing that exists today moves: `nvs` stays at
0x9000, `nvs_cc` at 0xF000, `phy_init` at 0x15000 and `factory` at 0x20000.
`adl_certs` lands at 0x120000 (24 KB), well inside the 4 MB flash. Check
with `idf.py partition-table` after the change.

Why a partition of its own:

- adl writes a whole NVS image, so it replaces everything in the target
  partition. Keeping the identity separate means flashing a cert never wipes
  Wi-Fi settings or calibration in `nvs`.
- `nvs_cc` belongs to the cc_comm library, which erases and initialises it
  itself. adl refuses to write there.
- A factory reset (`nvs_flash_erase()`) only clears `nvs`, so the identity
  survives it.

Boards need firmware with this table flashed (`idf.py flash` writes the
table too) before adl can write the identity. adl reads the table off the
board each time and refuses to write if `adl_certs` is missing or isn't a
data/nvs partition, so a wrong layout fails safely instead of overwriting
something else.

## 2. What is in it

Namespace `adl`, every value a NUL-terminated string:

| key | value |
|---|---|
| `device_id` | `GLXADL017` |
| `device_cert` | device certificate, PEM |
| `device_chain` | device certificate + intermediate, PEM |
| `device_key` | private key, PEM (PKCS#8, `BEGIN PRIVATE KEY`) |
| `ca_root` | root CA, PEM |

Use `device_chain` as the client certificate for TLS so the server gets the
intermediate too. The intermediate + root chain isn't stored: an RSA-4096
intermediate and root come to about 3,990 bytes, right at NVS's 4000 byte
string limit, and the device doesn't need it. adl checks every value
against the limit before touching the board.

The layout comes from `internal/espflash/adl-nvs.csv`. To change key names
or add values, pass a different CSV with `--nvs-template` (or
`ADL_NVS_TEMPLATE`). It's a normal Espressif `nvs_partition_gen` CSV with
`${ADL_DEVICE_ID}`, `${ADL_DEVICE_CERT}`, `${ADL_DEVICE_CHAIN}`,
`${ADL_DEVICE_KEY}`, `${ADL_CA_CHAIN}` and `${ADL_CA_ROOT}` placeholders.

## 3. Reading it

```c
#include <stdlib.h>
#include "esp_tls.h"
#include "nvs.h"
#include "nvs_flash.h"

#define ADL_PARTITION "adl_certs"
#define ADL_NAMESPACE "adl"

// Reads one string from the adl namespace. The caller frees it.
// *len includes the terminating NUL, which mbedTLS needs for PEM input.
static char *adl_read(nvs_handle_t h, const char *key, size_t *len)
{
    *len = 0;
    if (nvs_get_str(h, key, NULL, len) != ESP_OK) {
        return NULL;
    }
    char *buf = malloc(*len);
    if (buf != NULL && nvs_get_str(h, key, buf, len) != ESP_OK) {
        free(buf);
        return NULL;
    }
    return buf;
}

esp_err_t adl_identity_tls_cfg(esp_tls_cfg_t *cfg)
{
    esp_err_t err = nvs_flash_init_partition(ADL_PARTITION);
    if (err != ESP_OK) {
        return err;
    }
    nvs_handle_t h;
    err = nvs_open_from_partition(ADL_PARTITION, ADL_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return err; // ESP_ERR_NVS_NOT_FOUND: the board was never provisioned
    }
    size_t cert_len, key_len;
    char *cert = adl_read(h, "device_chain", &cert_len);
    char *key = adl_read(h, "device_key", &key_len);
    nvs_close(h);
    if (cert == NULL || key == NULL) {
        free(cert);
        free(key);
        return ESP_ERR_NOT_FOUND;
    }
    cfg->clientcert_buf = (const unsigned char *)cert;
    cfg->clientcert_bytes = cert_len;
    cfg->clientkey_buf = (const unsigned char *)key;
    cfg->clientkey_bytes = key_len;
    return ESP_OK;
}
```

Keep the buffers for as long as TLS connections use them. Don't call
`nvs_flash_erase_partition("adl_certs")` anywhere in the firmware.

## 4. Protecting the key

With this layout the private key is plaintext in flash. Anyone who can read the flash over USB can copy it.
For production hardware, the usual protection is flash encryption plus NVS
encryption. Both are one-way changes that burn eFuses, so they are a
deliberate product decision, not something adl does. If you turn on NVS
encryption, the adl_certs image has to be encrypted with the board's NVS
keys as well, and the flashing step needs to change to match. Talk to us
before enabling it.

## 5. Bringing up the first board

Do this on one board you don't mind losing before anything goes near the
line.

1. Build and flash firmware with the new partition table:
   `idf.py partition-table` should list `adl_certs` at 0x120000, then
   `idf.py -p /dev/ttyUSB0 flash`.
2. Mint and flash the identity: `adl mint --port /dev/ttyUSB0`. Note the
   device ID it prints.
3. Check it landed by reading the partition back:

   ```sh
   esptool.py --chip esp32s3 --port /dev/ttyUSB0 read_flash 0x120000 0x6000 adl_certs.bin
   strings adl_certs.bin | grep -c -- '-----BEGIN'   # 5
   grep -ac GLXADL017 adl_certs.bin                  # 1 (your device ID)
   ```

   Delete `adl_certs.bin` afterwards; it holds the private key.
4. Boot the firmware and check it loads the identity (section 3) and
   completes a TLS handshake with the backend.
5. Check nothing else moved: Wi-Fi settings in `nvs` and cc_comm's state
   in `nvs_cc` should survive step 2.

Then repeat with `adl eol provision` on a station before a real run.
