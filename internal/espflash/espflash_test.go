package espflash_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AUTORQ/adl-signing-server/internal/espflash"
	"github.com/AUTORQ/adl-signing-server/internal/espflash/espflashtest"
)

func TestParsePartitionTable(t *testing.T) {
	table, err := espflash.ParsePartitionTable(espflashtest.EncodeTable(espflashtest.ADLTable))
	if err != nil {
		t.Fatal(err)
	}
	if len(table) != len(espflashtest.ADLTable) {
		t.Fatalf("got %d partitions", len(table))
	}
	p, err := table.NVS("adl_certs")
	if err != nil || p.Offset != 0x120000 || p.Size != 0x6000 {
		t.Fatalf("adl_certs: %+v %v", p, err)
	}
	if _, err := table.NVS("phy_init"); err == nil {
		t.Error("phy_init is not nvs and should be refused")
	}
	_, err = table.NVS("certs")
	if err == nil || !strings.Contains(err.Error(), "certs, data, nvs, , 0x6000,") {
		t.Errorf("missing partition should say how to add it: %v", err)
	}
}

func TestParsePartitionTableRejectsCorruption(t *testing.T) {
	raw := espflashtest.EncodeTable(espflashtest.ADLTable)
	raw[40] ^= 0x01
	if _, err := espflash.ParsePartitionTable(raw); err == nil || !strings.Contains(err.Error(), "MD5") {
		t.Errorf("corrupt table: %v", err)
	}
	if _, err := espflash.ParsePartitionTable(bytes.Repeat([]byte{0xFF}, 0xC00)); err == nil {
		t.Error("blank flash should be refused")
	}
	if _, err := espflash.ParsePartitionTable(bytes.Repeat([]byte{0x12}, 0xC00)); err == nil {
		t.Error("garbage should be refused")
	}
}

func TestRender(t *testing.T) {
	out, err := espflash.Render(espflash.DefaultTemplate, testFiles("/w"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"adl,namespace,,", "device_id,data,string,GLXADL017", "device_key,file,string,/w/device.key"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered template lacks %q:\n%s", want, out)
		}
	}
	if _, err := espflash.Render("key,type,encoding,value\nx,file,string,${ADL_DEVICE_CRT}\n", testFiles("/w")); err == nil {
		t.Error("a typo in a placeholder should be an error")
	}
}

func testFiles(dir string) espflash.Files {
	return espflash.Files{
		DeviceID:    "GLXADL017",
		DeviceCert:  filepath.Join(dir, "device.crt"),
		DeviceChain: filepath.Join(dir, "device-chain.pem"),
		DeviceKey:   filepath.Join(dir, "device.key"),
		CAChain:     filepath.Join(dir, "ca-chain.pem"),
		CARoot:      filepath.Join(dir, "ca-root.pem"),
	}
}

func writeIdentity(t *testing.T, dir string, chainSize int) espflash.Files {
	t.Helper()
	f := testFiles(dir)
	pem := func(tag string, n int) []byte {
		body := strings.Repeat("A", n)
		return []byte("-----BEGIN " + tag + "-----\n" + body + "\n-----END " + tag + "-----\n")
	}
	for path, data := range map[string][]byte{
		f.DeviceCert:  pem("CERTIFICATE", 1500),
		f.DeviceChain: pem("CERTIFICATE", chainSize),
		f.DeviceKey:   pem("PRIVATE KEY", 1600),
		f.CAChain:     pem("CERTIFICATE", 3800),
		f.CARoot:      pem("CERTIFICATE", 1900),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestFlashWritesAdlCertsOnly(t *testing.T) {
	board := espflashtest.NewBoard(t, espflashtest.EncodeTable(espflashtest.ADLTable))
	work := t.TempDir()
	files := writeIdentity(t, work, 3500)
	var log bytes.Buffer
	n := &espflash.NVS{Esptool: board.Esptool, Port: "/dev/ttyUSB0", Generator: espflashtest.Generator(t), Out: &log}
	if err := n.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := n.Flash(context.Background(), work, files); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	img, offset := board.Image(t)
	if offset != "0x120000" {
		t.Errorf("wrote at %s, want adl_certs at 0x120000", offset)
	}
	if len(img) != 0x6000 {
		t.Fatalf("image is %d bytes, want the partition size", len(img))
	}
	key, _ := os.ReadFile(files.DeviceKey)
	if !bytes.Contains(img, bytes.TrimSpace(key)) {
		t.Error("image does not contain the device key")
	}
}

func TestFlashRefusesUnsafeTargets(t *testing.T) {
	board := espflashtest.NewBoard(t, espflashtest.EncodeTable(espflashtest.ADLTable))
	work := t.TempDir()
	files := writeIdentity(t, work, 3500)
	for _, part := range []string{"nvs_cc", "phy_init", "missing"} {
		n := &espflash.NVS{Esptool: board.Esptool, Port: "p", Partition: part, Generator: espflashtest.Generator(t)}
		if err := n.Flash(context.Background(), work, files); err == nil {
			t.Errorf("flashing %s should fail", part)
		}
	}
	if _, err := os.Stat(board.Written); err == nil {
		t.Error("something was written despite the refusals")
	}
}

func TestFlashCatchesOversizeStrings(t *testing.T) {
	board := espflashtest.NewBoard(t, espflashtest.EncodeTable(espflashtest.ADLTable))
	work := t.TempDir()
	files := writeIdentity(t, work, 4100)
	n := &espflash.NVS{Esptool: board.Esptool, Port: "p", Generator: espflashtest.Generator(t)}
	err := n.Flash(context.Background(), work, files)
	if err == nil || !strings.Contains(err.Error(), "NVS string limit") {
		t.Fatalf("expected a size error, got %v", err)
	}
	if _, err := os.Stat(board.Written); err == nil {
		t.Error("oversize identity reached the board")
	}
}
