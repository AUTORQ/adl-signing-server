package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/AUTORQ/adl-signing-server/internal/espflash"
)

const flashLong = `Write a device's certificate, chain, private key and root CA into the board's
adl_certs NVS partition, for a dev board on your desk.

The files come from certs/<ID>/device (what "adl mint" wrote). If they are
not there, adl fetches them from the server first (dev keys are backed up
there; prod keys are not).

Nothing here burns eFuses. The board needs firmware whose partition table
has an adl_certs partition; adl reads the table off the board and refuses
to write anywhere else. The NVS layout (namespace "adl"):

  device_id      GLXADL017
  device_cert    device certificate (PEM)
  device_chain   device certificate + intermediate (PEM)
  device_key     private key (PEM, PKCS#8)
  ca_root        root CA (PEM)

docs/firmware-nvs.md has the partition table line and the C code that
reads these.

ONE-TIME SETUP
  pip install esptool esp-idf-nvs-partition-gen
  (or use the Python from your ESP-IDF install via ADL_NVS_GEN, see below)`

func newFlashCommand() *cobra.Command {
	var (
		stage, port, dir, esptool, chip string
		nvs                             nvsOptions
	)
	cmd := &cobra.Command{
		Use:   "flash DEVICE_ID --port PORT",
		Short: "Write a device's cert and key into a dev board's NVS (no eFuses)",
		Long:  flashLong,
		Example: `  adl flash GLXADL017 --port /dev/ttyUSB0
  adl mint --port /dev/ttyUSB0             # mint and flash in one go
  ADL_NVS_GEN="$IDF_PYTHON_ENV_PATH/bin/python -m esp_idf_nvs_partition_gen" \
    adl flash GLXADL017 --port /dev/ttyUSB0`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDeviceArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			if port == "" {
				return errors.New("--port is required (or set ADL_PORT)")
			}
			flasher, err := nvs.build(esptool, chip, port, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			return flashDevice(cmd, flasher, stage, dir, args[0])
		},
	}
	f := cmd.Flags()
	f.StringVar(&port, "port", os.Getenv("ADL_PORT"), "serial port of the board, e.g. /dev/ttyUSB0 (env ADL_PORT)")
	f.StringVar(&dir, "dir", "certs", "where adl mint/fetch put the files")
	f.StringVar(&esptool, "esptool", envOr("ADL_ESPTOOL", "esptool.py"), "esptool command (env ADL_ESPTOOL)")
	f.StringVar(&chip, "chip", "esp32s3", "esptool chip type")
	serverFlag(cmd, &stage)
	nvs.bind(cmd)
	register(cmd, map[string]completeFunc{
		"port":    completeSerialPort,
		"dir":     completeDirs,
		"esptool": fixed("esptool.py", "esptool"),
		"chip":    fixed("esp32s3"),
	})
	return cmd
}

// flashDevice writes the device's files into NVS, fetching them from the
// server for stage when they aren't on disk.
func flashDevice(cmd *cobra.Command, flasher *espflash.NVS, stage, dir, id string) error {
	work, err := espflash.TempDir()
	if err != nil {
		return err
	}
	defer espflash.Wipe(work)

	files, ok := localFiles(dir, id)
	if !ok {
		fmt.Fprintf(cmd.OutOrStdout(), "no complete set of files for %s under %s, fetching from the server\n", id, dir)
		ctx := cmd.Context()
		c, err := newClient(ctx, stage)
		if err != nil {
			return err
		}
		b, err := c.Bundle(ctx, id, "", true)
		if err != nil {
			return fmt.Errorf("fetching %s (prod keys are never stored on the server, so a prod board can only be flashed from its original files): %w", id, err)
		}
		if _, err := writeBundle(io.Discard, work, b, false); err != nil {
			return err
		}
		if files, ok = localFiles(work, id); !ok {
			return fmt.Errorf("the server's bundle for %s is incomplete", id)
		}
	}
	if err := flasher.Flash(cmd.Context(), work, files); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "flashed %s to %s (partition %s)\n", id, flasher.Port, flasher.Partition)
	return nil
}

// localFiles finds what writeBundle laid out for id under dir.
func localFiles(dir, id string) (espflash.Files, bool) {
	d := filepath.Join(dir, id, "device")
	f := espflash.Files{
		DeviceID:    id,
		DeviceCert:  filepath.Join(d, "device-"+id+".crt"),
		DeviceChain: filepath.Join(d, "device-"+id+"-chain.pem"),
		DeviceKey:   filepath.Join(d, "device-"+id+".key"),
		CAChain:     filepath.Join(d, "ca-chain.pem"),
		CARoot:      filepath.Join(d, "ca-root.pem"),
	}
	for _, p := range []string{f.DeviceCert, f.DeviceChain, f.DeviceKey, f.CAChain, f.CARoot} {
		if _, err := os.Stat(p); err != nil {
			return f, false
		}
	}
	return f, true
}

// nvsOptions are the NVS flags shared by adl flash, adl mint and adl eol.
type nvsOptions struct {
	partition, template, generator, tableOffset string
}

func (o *nvsOptions) bind(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.partition, "nvs-partition", envOr("ADL_NVS_PARTITION", espflash.DefaultPartition), "NVS partition to write (env ADL_NVS_PARTITION)")
	f.StringVar(&o.template, "nvs-template", os.Getenv("ADL_NVS_TEMPLATE"), "nvs_partition_gen CSV with ${ADL_*} placeholders (default: the built-in layout; env ADL_NVS_TEMPLATE)")
	f.StringVar(&o.generator, "nvs-gen", envOr("ADL_NVS_GEN", strings.Join(espflash.DefaultGenerator, " ")), "command that runs Espressif's nvs_partition_gen (env ADL_NVS_GEN)")
	f.StringVar(&o.tableOffset, "partition-table-offset", "0x8000", "CONFIG_PARTITION_TABLE_OFFSET of the firmware")
	register(cmd, map[string]completeFunc{
		"nvs-partition":          fixed(espflash.DefaultPartition),
		"nvs-template":           completeCSV,
		"nvs-gen":                fixed(strings.Join(espflash.DefaultGenerator, " ")),
		"partition-table-offset": fixed("0x8000"),
	})
}

func (o *nvsOptions) build(esptool, chip, port string, out io.Writer) (*espflash.NVS, error) {
	n := &espflash.NVS{
		Esptool: esptool, Chip: chip, Port: port, Out: out,
		Partition: o.partition, Generator: strings.Fields(o.generator),
	}
	if o.template != "" {
		data, err := os.ReadFile(o.template)
		if err != nil {
			return nil, err
		}
		n.Template = string(data)
	}
	off, err := strconv.ParseUint(o.tableOffset, 0, 32)
	if err != nil {
		return nil, fmt.Errorf("--partition-table-offset: %w", err)
	}
	n.TableOffset = uint32(off)
	return n, nil
}

func completeCSV(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return []string{"csv"}, cobra.ShellCompDirectiveFilterFileExt
}
