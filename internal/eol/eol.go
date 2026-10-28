// Package eol runs the end-of-line provisioning step for ESP32-S3 boards:
// read the chip's MAC, generate a key on the station, get it signed, flash
// it, and confirm back to the server.
//
// The device private key only ever exists in station memory and, for the
// duration of the flash, in a tmpfs directory that is wiped afterwards. It is
// never sent to the server for prod.
//
// By default the identity goes into the board's adl_certs NVS partition
// (see internal/espflash). A custom flash script can replace that step.
package eol

import (
	"bufio"
	"context"
	"crypto"
	"crypto/x509/pkix"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AUTORQ/adl-signing-server/internal/client"
	"github.com/AUTORQ/adl-signing-server/internal/espflash"
	"github.com/AUTORQ/adl-signing-server/internal/model"
	"github.com/AUTORQ/adl-signing-server/internal/pki"
)

// Station holds the settings for one EoL station.
type Station struct {
	Client *client.Client
	Env    string
	Name   string
	Port   string
	// Chip is passed to esptool (--chip), esp32s3 by default.
	Chip string
	// Esptool is the esptool command, e.g. "esptool.py" or "esptool".
	Esptool string
	// NVS writes the credentials into an NVS partition. It is used unless
	// FlashScript is set.
	NVS *espflash.NVS
	// FlashScript, when set, replaces the NVS step. It gets its inputs as
	// ADL_* environment variables; see docs/eol-provisioning.md.
	FlashScript string
	// VerifyScript (optional) runs after flashing, e.g. boots the board and
	// checks it can reach the cloud with its new identity.
	VerifyScript string
	Firmware     string
	KeyType      string
	LogPath      string
	Out          io.Writer
	// ReadMAC can be replaced in tests.
	ReadMAC func(ctx context.Context) (string, error)
	// FlashTimeout bounds the flash and verify scripts.
	FlashTimeout time.Duration
}

// Options for one provisioning run.
type Options struct {
	// DeviceID pins the identity; normally the server allocates one.
	DeviceID string
	// Reissue re-keys a chip that is already provisioned. Needs the
	// <env>:revoke permission.
	Reissue bool
	Notes   string
	Labels  map[string]string
}

type Result struct {
	DeviceID string
	Serial   string
	ChipID   string
	Reissued bool
}

func (s *Station) printf(format string, args ...any) {
	if s.Out != nil {
		fmt.Fprintf(s.Out, format, args...)
	}
}

var macRE = regexp.MustCompile(`(?m)^MAC:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})`)

// ReadChipMAC asks esptool for the factory MAC burned into eFuse.
func (s *Station) ReadChipMAC(ctx context.Context) (string, error) {
	if s.ReadMAC != nil {
		return s.ReadMAC(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	args := []string{"--chip", s.chip(), "--port", s.Port, "read_mac"}
	out, err := exec.CommandContext(ctx, s.Esptool, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w\n%s", s.Esptool, strings.Join(args, " "), err, out)
	}
	m := macRE.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("could not find MAC in esptool output:\n%s", out)
	}
	return strings.ToLower(strings.ReplaceAll(string(m[1]), ":", "")), nil
}

func (s *Station) chip() string {
	if s.Chip == "" {
		return "esp32s3"
	}
	return s.Chip
}

// nvs is the station's NVS settings with its board details filled in.
func (s *Station) nvs() *espflash.NVS {
	n := *s.NVS
	n.Port, n.Chip, n.Esptool, n.Out = s.Port, s.chip(), s.Esptool, s.Out
	return &n
}

// Preflight checks the station is usable before an operator starts a shift.
func (s *Station) Preflight(ctx context.Context) error {
	var problems []string
	if s.ReadMAC == nil {
		if _, err := exec.LookPath(s.Esptool); err != nil {
			problems = append(problems, fmt.Sprintf("esptool not found (%s): pip install esptool", s.Esptool))
		}
	}
	switch {
	case s.FlashScript != "":
		if st, err := os.Stat(s.FlashScript); err != nil || st.Mode()&0o111 == 0 {
			problems = append(problems, fmt.Sprintf("flash script %q missing or not executable", s.FlashScript))
		}
	case s.NVS == nil:
		problems = append(problems, "no flash method configured")
	default:
		if err := s.nvs().Check(ctx); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if s.VerifyScript != "" {
		if st, err := os.Stat(s.VerifyScript); err != nil || st.Mode()&0o111 == 0 {
			problems = append(problems, fmt.Sprintf("verify script %q missing or not executable", s.VerifyScript))
		}
	}
	if strings.TrimSpace(s.Name) == "" {
		problems = append(problems, "station name is not set (--station or ADL_STATION)")
	}
	who, err := s.Client.WhoAmI(ctx)
	if err != nil {
		problems = append(problems, "cannot reach signing server: "+err.Error())
	} else {
		s.printf("signed in as %s\n", who.Principal)
		for _, perm := range []string{s.Env + ":issue", s.Env + ":provision", s.Env + ":read"} {
			if !hasPerm(who.Permissions, perm) {
				problems = append(problems, "this identity lacks "+perm)
			}
		}
		if ca, err := s.Client.CAStatus(ctx, s.Env); err != nil || !ca.Configured {
			problems = append(problems, s.Env+" CA is not configured on the server")
		} else {
			s.printf("%s CA: %s (expires %s)\n", s.Env, ca.Subject, ca.NotAfter.Format("2006-01-02"))
		}
	}
	if len(problems) > 0 {
		return errors.New("station not ready:\n  - " + strings.Join(problems, "\n  - "))
	}
	return nil
}

func hasPerm(perms []string, want string) bool {
	for _, p := range perms {
		if p == "*" || p == want || (strings.HasSuffix(p, ":*") && strings.HasPrefix(want, strings.TrimSuffix(p, "*"))) {
			return true
		}
	}
	return false
}

// Provision runs the whole EoL sequence for the board on s.Port.
func (s *Station) Provision(ctx context.Context, o Options) (*Result, error) {
	s.printf("reading chip id on %s ...\n", s.Port)
	mac, err := s.ReadChipMAC(ctx)
	if err != nil {
		return nil, err
	}
	s.printf("chip mac %s\n", mac)

	key, err := pki.GenerateKey(s.KeyType)
	if err != nil {
		return nil, err
	}
	csr, err := pki.CreateCSR(key, pkix.Name{CommonName: "pending"})
	if err != nil {
		return nil, err
	}

	req := model.IssueRequest{Env: s.Env, DeviceID: o.DeviceID, CSR: string(csr), ChipID: mac, Labels: o.Labels}
	resp, err := s.Client.Issue(ctx, req)
	reissued := false
	if ae, ok := client.IsCode(err, "chip_already_assigned"); ok {
		// This chip has been through a station before. If it never got
		// confirmed (power cut, flash failure, operator pulled the cable)
		// we just re-key the same identity. If it was confirmed, only do
		// that when explicitly asked.
		existing := ae.Details["device_id"]
		dev, gerr := s.Client.GetDevice(ctx, existing)
		if gerr != nil {
			return nil, fmt.Errorf("chip %s belongs to %s, and looking it up failed: %w", mac, existing, gerr)
		}
		if dev.Device.Status == model.DeviceProvisioned && !o.Reissue {
			return nil, fmt.Errorf("chip %s is already provisioned as %s; pass --reissue to re-key it (revokes the old certificate)", mac, existing)
		}
		if o.DeviceID != "" && o.DeviceID != existing {
			return nil, fmt.Errorf("chip %s belongs to %s, not %s", mac, existing, o.DeviceID)
		}
		s.printf("chip already registered as %s (%s), re-issuing\n", existing, dev.Device.Status)
		req.DeviceID, req.Replace = existing, true
		resp, err = s.Client.Issue(ctx, req)
		reissued = true
	}
	if err != nil {
		return nil, fmt.Errorf("issue certificate: %w", err)
	}
	id, serial := resp.Device.ID, resp.Certificate.Serial
	s.printf("issued %s serial %s\n", id, serial)

	if err := s.flash(ctx, key, resp, mac); err != nil {
		s.logRun(id, serial, mac, "FLASH_FAILED", err.Error())
		return nil, fmt.Errorf("%s was issued but flashing failed, re-run on the same board to retry: %w", id, err)
	}

	if _, err := s.Client.Provisioned(ctx, id, model.ProvisionRequest{
		Serial: serial, ChipID: mac, Station: s.Name, FirmwareVersion: s.Firmware, Notes: o.Notes,
	}); err != nil {
		s.logRun(id, serial, mac, "CONFIRM_FAILED", err.Error())
		return nil, fmt.Errorf("%s flashed but the server did not record it; re-run on the same board: %w", id, err)
	}
	s.logRun(id, serial, mac, "PASS", "")
	return &Result{DeviceID: id, Serial: serial, ChipID: mac, Reissued: reissued}, nil
}

// flash writes the credentials to a private tmpfs directory, writes them to
// the board (NVS, or the flash script), runs the verify script, then wipes
// the directory.
func (s *Station) flash(ctx context.Context, key crypto.Signer, resp *model.IssueResponse, mac string) error {
	dir, err := espflash.TempDir()
	if err != nil {
		return err
	}
	defer espflash.Wipe(dir)

	keyPEM, err := pki.EncodePrivateKey(key)
	if err != nil {
		return err
	}
	chain, err := pki.ParseCertificates([]byte(resp.ChainPEM))
	if err != nil {
		return err
	}
	leaf, err := pki.ParseCertificates([]byte(resp.CertificatePEM))
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"device.key":       keyPEM,
		"device.crt":       []byte(resp.CertificatePEM),
		"device-chain.pem": pki.EncodeCertificates(leaf[0], chain[0]),
		"ca-chain.pem":     []byte(resp.ChainPEM),
		"ca-root.pem":      pki.EncodeCertificates(chain[len(chain)-1]),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	env := append(os.Environ(),
		"ADL_PORT="+s.Port,
		"ADL_CHIP="+s.chip(),
		"ADL_ESPTOOL="+s.Esptool,
		"ADL_DEVICE_ID="+resp.Device.ID,
		"ADL_SERIAL="+resp.Certificate.Serial,
		"ADL_CHIP_MAC="+mac,
		"ADL_ENV="+s.Env,
		"ADL_KEY_ALGORITHM="+resp.Certificate.KeyAlgorithm,
		"ADL_WORK_DIR="+dir,
		"ADL_DEVICE_KEY="+filepath.Join(dir, "device.key"),
		"ADL_DEVICE_CERT="+filepath.Join(dir, "device.crt"),
		"ADL_DEVICE_CHAIN="+filepath.Join(dir, "device-chain.pem"),
		"ADL_CA_CHAIN="+filepath.Join(dir, "ca-chain.pem"),
		"ADL_CA_ROOT="+filepath.Join(dir, "ca-root.pem"),
	)
	timeout := s.FlashTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	if s.FlashScript != "" {
		if err := s.runScript(ctx, "flash", s.FlashScript, env, timeout); err != nil {
			return err
		}
	} else {
		if err := s.nvs().Flash(ctx, dir, espflash.Files{
			DeviceID:    resp.Device.ID,
			DeviceCert:  filepath.Join(dir, "device.crt"),
			DeviceChain: filepath.Join(dir, "device-chain.pem"),
			DeviceKey:   filepath.Join(dir, "device.key"),
			CAChain:     filepath.Join(dir, "ca-chain.pem"),
			CARoot:      filepath.Join(dir, "ca-root.pem"),
		}); err != nil {
			return err
		}
	}
	if s.VerifyScript != "" {
		if err := s.runScript(ctx, "verify", s.VerifyScript, env, timeout); err != nil {
			return err
		}
	}
	return nil
}

func (s *Station) runScript(ctx context.Context, what, path string, env []string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	s.printf("running %s script %s\n", what, path)
	cmd := exec.CommandContext(ctx, path)
	cmd.Env = env
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			s.printf("  | %s\n", sc.Text())
		}
		close(done)
	}()
	err := cmd.Run()
	pw.Close()
	<-done
	if err != nil {
		return fmt.Errorf("%s script failed: %w", what, err)
	}
	return nil
}

// logRun appends one line per board to the station's CSV log, which is
// handy when someone asks "what did line 2 do on Tuesday".
func (s *Station) logRun(id, serial, mac, result, detail string) {
	if s.LogPath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.LogPath), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(s.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{time.Now().UTC().Format(time.RFC3339), s.Name, s.Env, id, serial, mac, s.Firmware, result, detail})
	w.Flush()
}
