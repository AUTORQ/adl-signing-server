// Package espflash writes a device identity into an NVS partition on an
// ESP32-S3. It is the default flashing path for both `adl flash` (dev
// boards) and `adl eol provision` (factory).
//
// The steps follow Espressif's manufacturing flow: read the partition table
// off the board, find the target NVS partition by name, build an NVS image
// from a CSV with Espressif's nvs_partition_gen, and write it with esptool.
// Nothing here touches eFuses.
//
// The whole partition is replaced, so the target should be a partition that
// holds only the identity (adl_certs by default), never the app's general
// nvs partition or cc_comm's nvs_cc.
package espflash

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultPartition is the NVS partition the identity is written to.
	DefaultPartition = "adl_certs"
	// DefaultTableOffset is CONFIG_PARTITION_TABLE_OFFSET's default.
	DefaultTableOffset = 0x8000
	// tableSize is how much of the table esptool reads (ESP-IDF's maximum).
	tableSize = 0xC00
	// maxNVSString is NVS's limit for one string value, terminator included.
	maxNVSString = 4000
)

// DefaultGenerator runs Espressif's NVS image generator
// (pip install esp-idf-nvs-partition-gen).
var DefaultGenerator = []string{"python3", "-m", "esp_idf_nvs_partition_gen"}

// DefaultTemplate is the NVS layout the firmware reads. See
// docs/firmware-nvs.md for the matching C code.
//
//go:embed adl-nvs.csv
var DefaultTemplate string

// partitions the flasher refuses to overwrite, with the reason.
var protected = map[string]string{
	"nvs_cc": "it belongs to the cc_comm library, which erases and manages it itself",
}

// Files are the identity files to write, as paths on disk.
type Files struct {
	DeviceID    string
	DeviceCert  string
	DeviceChain string
	DeviceKey   string
	CAChain     string
	CARoot      string
}

// vars are the ${...} names a template can use.
func (f Files) vars() map[string]string {
	return map[string]string{
		"ADL_DEVICE_ID":    f.DeviceID,
		"ADL_DEVICE_CERT":  f.DeviceCert,
		"ADL_DEVICE_CHAIN": f.DeviceChain,
		"ADL_DEVICE_KEY":   f.DeviceKey,
		"ADL_CA_CHAIN":     f.CAChain,
		"ADL_CA_ROOT":      f.CARoot,
	}
}

// NVS flashes an identity into an NVS partition.
type NVS struct {
	Esptool string
	Chip    string
	Port    string
	// Partition is the target partition's name (DefaultPartition if empty).
	Partition string
	// TableOffset is where the partition table lives (DefaultTableOffset if 0).
	TableOffset uint32
	// Template is the nvs_partition_gen CSV with ${ADL_*} placeholders
	// (DefaultTemplate if empty).
	Template string
	// Generator is the nvs_partition_gen command (DefaultGenerator if nil).
	Generator []string
	// Out gets progress lines and tool output.
	Out io.Writer
}

func (n *NVS) partition() string {
	if n.Partition == "" {
		return DefaultPartition
	}
	return n.Partition
}

func (n *NVS) tableOffset() uint32 {
	if n.TableOffset == 0 {
		return DefaultTableOffset
	}
	return n.TableOffset
}

func (n *NVS) template() string {
	if n.Template == "" {
		return DefaultTemplate
	}
	return n.Template
}

func (n *NVS) generator() []string {
	if len(n.Generator) == 0 {
		return DefaultGenerator
	}
	return n.Generator
}

func (n *NVS) chip() string {
	if n.Chip == "" {
		return "esp32s3"
	}
	return n.Chip
}

func (n *NVS) printf(format string, args ...any) {
	if n.Out != nil {
		fmt.Fprintf(n.Out, format, args...)
	}
}

// Check confirms the tools are installed and the template is usable,
// without touching a board.
func (n *NVS) Check(ctx context.Context) error {
	var problems []string
	if _, err := exec.LookPath(n.Esptool); err != nil {
		problems = append(problems, fmt.Sprintf("esptool not found (%s): pip install esptool", n.Esptool))
	}
	gen := n.generator()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, gen[0], append(gen[1:], "--help")...).CombinedOutput(); err != nil {
		problems = append(problems, fmt.Sprintf("NVS generator %q does not run (pip install esp-idf-nvs-partition-gen, or set ADL_NVS_GEN): %v %s",
			strings.Join(gen, " "), err, firstLine(out)))
	}
	if _, err := Render(n.template(), Files{}.placeholders()); err != nil {
		problems = append(problems, "NVS template: "+err.Error())
	}
	if reason, ok := protected[n.partition()]; ok {
		problems = append(problems, fmt.Sprintf("will not write partition %q: %s", n.partition(), reason))
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n  - "))
	}
	return nil
}

// placeholders fills every variable so Check can validate a template
// without real files.
func (Files) placeholders() Files {
	return Files{DeviceID: "x", DeviceCert: "x", DeviceChain: "x", DeviceKey: "x", CAChain: "x", CARoot: "x"}
}

// Flash writes files into the board's NVS partition. workDir is where the
// rendered CSV and the image go; the caller owns and wipes it.
func (n *NVS) Flash(ctx context.Context, workDir string, files Files) error {
	if reason, ok := protected[n.partition()]; ok {
		return fmt.Errorf("will not write partition %q: %s", n.partition(), reason)
	}
	if err := checkSizes(n.template(), files); err != nil {
		return err
	}

	n.printf("reading partition table at %#x\n", n.tableOffset())
	tablePath := filepath.Join(workDir, "partition-table.bin")
	if err := n.esptool(ctx, "read_flash", hex(n.tableOffset()), hex(tableSize), tablePath); err != nil {
		return err
	}
	raw, err := os.ReadFile(tablePath)
	if err != nil {
		return err
	}
	table, err := ParsePartitionTable(raw)
	if err != nil {
		return fmt.Errorf("partition table on the board: %w", err)
	}
	part, err := table.NVS(n.partition())
	if err != nil {
		return err
	}
	n.printf("target partition %s at %#x (%d bytes)\n", part.Name, part.Offset, part.Size)

	csv, err := Render(n.template(), files)
	if err != nil {
		return err
	}
	csvPath := filepath.Join(workDir, "nvs.csv")
	if err := os.WriteFile(csvPath, []byte(csv), 0o600); err != nil {
		return err
	}
	imgPath := filepath.Join(workDir, "nvs.bin")
	gen := n.generator()
	args := append(gen[1:len(gen):len(gen)], "generate", csvPath, imgPath, hex(part.Size))
	if err := n.run(ctx, gen[0], args...); err != nil {
		return fmt.Errorf("building NVS image: %w", err)
	}
	if st, err := os.Stat(imgPath); err != nil || st.Size() != int64(part.Size) {
		return fmt.Errorf("NVS image is not %d bytes as expected", part.Size)
	}

	n.printf("writing %s\n", part.Name)
	return n.esptool(ctx, "write_flash", hex(part.Offset), imgPath)
}

func (n *NVS) esptool(ctx context.Context, args ...string) error {
	full := append([]string{"--chip", n.chip(), "--port", n.Port}, args...)
	return n.run(ctx, n.Esptool, full...)
}

// run streams a tool's output, indented, and includes its last lines in
// the error if it fails.
func (n *NVS) run(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	var tail []string
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			n.printf("  | %s\n", sc.Text())
			tail = append(tail, sc.Text())
			if len(tail) > 5 {
				tail = tail[1:]
			}
		}
		close(done)
	}()
	err := cmd.Run()
	pw.Close()
	<-done
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.Join(tail, "\n"))
	}
	return nil
}

// Render fills ${ADL_*} placeholders in a template. An unknown or empty
// placeholder is an error, so a typo can't flash an empty value.
func Render(template string, files Files) (string, error) {
	vars := files.vars()
	var missing []string
	out := os.Expand(template, func(name string) string {
		v, ok := vars[name]
		if !ok || v == "" {
			missing = append(missing, name)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("template uses unknown or empty ${%s}", strings.Join(missing, "}, ${"))
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "key,type,encoding,value") {
		return "", errors.New(`template must start with the header "key,type,encoding,value"`)
	}
	return out, nil
}

// checkSizes catches PEM files too big for an NVS string before esptool
// gets anywhere near the board.
func checkSizes(template string, files Files) error {
	for name, path := range files.vars() {
		if name == "ADL_DEVICE_ID" || !strings.Contains(template, "${"+name+"}") {
			continue
		}
		if !usedAsString(template, name) {
			continue
		}
		st, err := os.Stat(path)
		if err != nil {
			return err
		}
		if st.Size()+1 > maxNVSString {
			return fmt.Errorf("%s is %d bytes, over the %d byte NVS string limit; store it with the binary encoding or drop it from the template",
				filepath.Base(path), st.Size(), maxNVSString-1)
		}
	}
	return nil
}

func usedAsString(template, name string) bool {
	for _, line := range strings.Split(template, "\n") {
		f := strings.Split(strings.TrimSpace(line), ",")
		if len(f) == 4 && f[1] == "file" && f[2] == "string" && f[3] == "${"+name+"}" {
			return true
		}
	}
	return false
}

// Partition is one entry of an ESP-IDF partition table.
type Partition struct {
	Name    string
	Type    uint8
	SubType uint8
	Offset  uint32
	Size    uint32
	Flags   uint32
}

const (
	typeData    = 0x01
	subtypeNVS  = 0x02
	entrySize   = 32
	magicEntry  = 0x50AA // bytes AA 50
	magicMD5    = 0xEBEB
	labelLength = 16
)

// Table is a parsed partition table.
type Table []Partition

// ParsePartitionTable decodes the binary table ESP-IDF writes at 0x8000,
// checking the MD5 entry when there is one.
func ParsePartitionTable(raw []byte) (Table, error) {
	var t Table
	for off := 0; off+entrySize <= len(raw); off += entrySize {
		e := raw[off : off+entrySize]
		switch binary.LittleEndian.Uint16(e) {
		case magicEntry:
			label := e[12 : 12+labelLength]
			if i := bytes.IndexByte(label, 0); i >= 0 {
				label = label[:i]
			}
			t = append(t, Partition{
				Name:    string(label),
				Type:    e[2],
				SubType: e[3],
				Offset:  binary.LittleEndian.Uint32(e[4:]),
				Size:    binary.LittleEndian.Uint32(e[8:]),
				Flags:   binary.LittleEndian.Uint32(e[28:]),
			})
		case magicMD5:
			sum := md5.Sum(raw[:off])
			if !bytes.Equal(sum[:], e[16:32]) {
				return nil, errors.New("MD5 does not match; the table is corrupt or the offset is wrong")
			}
			return t.valid()
		default:
			if bytes.Equal(e, bytes.Repeat([]byte{0xFF}, entrySize)) {
				return t.valid()
			}
			return nil, fmt.Errorf("unexpected data at entry %d; is the partition table really at this offset?", off/entrySize)
		}
	}
	return t.valid()
}

func (t Table) valid() (Table, error) {
	if len(t) == 0 {
		return nil, errors.New("no partitions found; is the board flashed with firmware yet?")
	}
	return t, nil
}

// NVS finds the named partition and checks it really is an NVS partition.
func (t Table) NVS(name string) (Partition, error) {
	for _, p := range t {
		if p.Name != name {
			continue
		}
		if p.Type != typeData || p.SubType != subtypeNVS {
			return p, fmt.Errorf("partition %q is not data/nvs (type %#x subtype %#x)", name, p.Type, p.SubType)
		}
		return p, nil
	}
	names := make([]string, len(t))
	for i, p := range t {
		names[i] = p.Name
	}
	return Partition{}, fmt.Errorf("the board has no %q partition (it has: %s). Add this line to the firmware's partition CSV and reflash the firmware:\n    %s, data, nvs, , 0x6000,",
		name, strings.Join(names, ", "), name)
}

func hex(v uint32) string { return "0x" + strconv.FormatUint(uint64(v), 16) }

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return s
}

// TempDir makes a private working directory, on RAM-backed storage where
// there is some, so key material never touches disk.
func TempDir() (string, error) {
	if runtime.GOOS == "linux" {
		if st, err := os.Stat("/dev/shm"); err == nil && st.IsDir() {
			return os.MkdirTemp("/dev/shm", "adl-flash-")
		}
	}
	return os.MkdirTemp("", "adl-flash-")
}

// Wipe overwrites then removes every file in dir. On tmpfs the overwrite is
// mostly ceremony; on a real disk it is best effort.
func Wipe(dir string) {
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
				_, _ = f.Write(make([]byte, info.Size()))
				_ = f.Sync()
				_ = f.Close()
			}
		}
		return nil
	})
	_ = os.RemoveAll(dir)
}
