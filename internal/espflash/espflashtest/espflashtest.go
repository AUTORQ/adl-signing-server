// Package espflashtest fakes the tools espflash drives, so flashing can be
// tested without a board.
package espflashtest

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AUTORQ/adl-signing-server/internal/espflash"
)

// ADLTable is the ADL board's table (cc_partitions.csv, as read off a
// real build) with adl_certs added at the end, the way docs/firmware-nvs.md
// tells the firmware to. Nothing before it moves.
var ADLTable = []espflash.Partition{
	{Name: "nvs", Type: 1, SubType: 2, Offset: 0x9000, Size: 0x6000},
	{Name: "nvs_cc", Type: 1, SubType: 2, Offset: 0xF000, Size: 0x6000},
	{Name: "phy_init", Type: 1, SubType: 1, Offset: 0x15000, Size: 0x1000},
	{Name: "factory", Type: 0, SubType: 0, Offset: 0x20000, Size: 0x100000},
	{Name: "adl_certs", Type: 1, SubType: 2, Offset: 0x120000, Size: 0x6000},
}

// EncodeTable builds the binary gen_esp32part.py would, MD5 entry included.
func EncodeTable(parts []espflash.Partition) []byte {
	var b bytes.Buffer
	for _, p := range parts {
		e := make([]byte, 32)
		e[0], e[1], e[2], e[3] = 0xAA, 0x50, p.Type, p.SubType
		binary.LittleEndian.PutUint32(e[4:], p.Offset)
		binary.LittleEndian.PutUint32(e[8:], p.Size)
		copy(e[12:28], p.Name)
		binary.LittleEndian.PutUint32(e[28:], p.Flags)
		b.Write(e)
	}
	sum := md5.Sum(b.Bytes())
	m := bytes.Repeat([]byte{0xFF}, 32)
	m[0], m[1] = 0xEB, 0xEB
	copy(m[16:], sum[:])
	b.Write(m)
	for b.Len() < 0xC00 {
		b.WriteByte(0xFF)
	}
	return b.Bytes()
}

// MAC is what the fake board reports to read_mac.
const MAC = "f4:12:fa:0a:0c:01"

// Board is a fake esptool. read_mac reports MAC, reads of the partition
// table return Table, and writes land in Written, with the offset in
// Written + ".offset".
type Board struct {
	Esptool string
	Written string
}

// NewBoard writes the fake esptool script into a temp dir.
func NewBoard(t testing.TB, table []byte) *Board {
	t.Helper()
	dir := t.TempDir()
	tablePath := filepath.Join(dir, "table.bin")
	if err := os.WriteFile(tablePath, table, 0o600); err != nil {
		t.Fatal(err)
	}
	b := &Board{Esptool: filepath.Join(dir, "esptool"), Written: filepath.Join(dir, "written")}
	script := `#!/bin/sh
set -e
while [ $# -gt 0 ]; do
  case "$1" in
    read_mac) echo "MAC: ` + MAC + `"; exit 0 ;;
    read_flash) cp "` + tablePath + `" "$4"; exit 0 ;;
    write_flash) echo "$2" > "` + b.Written + `.offset"; cp "$3" "` + b.Written + `"; exit 0 ;;
  esac
  shift
done
exit 1
`
	if err := os.WriteFile(b.Esptool, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return b
}

// Image returns what was written and the offset it went to.
func (b *Board) Image(t testing.TB) ([]byte, string) {
	t.Helper()
	img, err := os.ReadFile(b.Written)
	if err != nil {
		t.Fatalf("nothing was written to the board: %v", err)
	}
	off, _ := os.ReadFile(b.Written + ".offset")
	return img, strings.TrimSpace(string(off))
}

// Generator is Espressif's nvs_partition_gen when ADL_TEST_NVS_GEN names
// it, otherwise a stand-in that writes a correctly sized file holding the
// CSV followed by every file it names.
func Generator(t testing.TB) []string {
	t.Helper()
	if g := os.Getenv("ADL_TEST_NVS_GEN"); g != "" {
		return strings.Fields(g)
	}
	path := filepath.Join(t.TempDir(), "nvsgen")
	script := `#!/bin/sh
[ "$1" = "--help" ] && exit 0
[ "$1" = "generate" ] || exit 1
{ cat "$2"; grep ',file,' "$2" | cut -d, -f4 | xargs cat; } > "$3"
truncate -s "$(($4))" "$3"
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return []string{path}
}
