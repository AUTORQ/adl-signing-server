// Package e2e drives the real HTTP API through the real client, with SigV4
// auth checked by a fake STS, and runs the EoL station flow against it.
package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AUTORQ/adl-signing-server/internal/auth"
	"github.com/AUTORQ/adl-signing-server/internal/auth/authtest"
	"github.com/AUTORQ/adl-signing-server/internal/client"
	"github.com/AUTORQ/adl-signing-server/internal/eol"
	"github.com/AUTORQ/adl-signing-server/internal/espflash"
	"github.com/AUTORQ/adl-signing-server/internal/espflash/espflashtest"
	"github.com/AUTORQ/adl-signing-server/internal/localstack"
	"github.com/AUTORQ/adl-signing-server/internal/model"
	"github.com/AUTORQ/adl-signing-server/internal/pki"
	"github.com/AUTORQ/adl-signing-server/internal/store"
)

const (
	devARN     = "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_ADLDeveloper_0123/jane@globex.us"
	stationARN = "arn:aws:sts::111111111111:assumed-role/adl-factory-station/line-1"
	adminARN   = "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_ADLCAAdmin_0123/alex@globex.example"
)

type env struct {
	sts    *authtest.STS
	client *client.Client
	stack  *localstack.Stack
}

func setup(t *testing.T) *env {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := localstack.New(log)
	if err != nil {
		t.Fatal(err)
	}
	sts := authtest.NewSTS(devARN)
	t.Cleanup(sts.Close)
	verifier := &auth.STSVerifier{
		Audience: "adl-e2e", Regions: []string{"us-east-1"}, Endpoint: sts.Endpoint, Nonces: store.NewMemory(),
		Policy: &auth.Policy{
			Accounts: []string{authtest.Account},
			Bindings: []auth.Binding{
				{Roles: []string{"AWSReservedSSO_ADLDeveloper_*"}, Permissions: []string{"dev:issue", "dev:read", "dev:key-read"}},
				{Roles: []string{"adl-factory-station"}, Permissions: []string{"prod:issue", "prod:read", "prod:provision"}},
				{Roles: []string{"AWSReservedSSO_ADLCAAdmin_*"}, Permissions: []string{"*"}},
			},
		},
	}
	srv := httptest.NewServer(st.Handler(verifier, log))
	t.Cleanup(srv.Close)
	c, err := client.NewWithTokens(srv.URL, &auth.TokenSigner{
		Credentials: authtest.Credentials(), Region: "us-east-1", Audience: "adl-e2e", Endpoint: sts.Endpoint,
	}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return &env{sts: sts, client: c, stack: st}
}

func TestDeveloperFlowOverHTTP(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	who, err := e.client.WhoAmI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if who.Principal != "AWSReservedSSO_ADLDeveloper_0123/jane@globex.us" {
		t.Errorf("whoami %+v", who)
	}
	if len(who.Environments) != 1 || who.Environments[0].Name != "dev" || strings.Join(who.Environments[0].Actions, " ") != "issue read key-read" {
		t.Errorf("whoami environments %+v", who.Environments)
	}
	if name, err := client.ResolveEnv(who.Environments, "", "dev"); err != nil || name != "dev" {
		t.Errorf("resolve dev: %q %v", name, err)
	}

	key, _ := pki.GenerateKey("rsa2048")
	csr, _ := pki.CreateCSR(key, pkix.Name{})
	keyPEM, _ := pki.EncodePrivateKey(key)
	resp, err := e.client.Issue(ctx, model.IssueRequest{Env: "dev", CSR: string(csr), PrivateKey: string(keyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.client.Bundle(ctx, resp.Device.ID, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if b.PrivateKeyPEM != string(keyPEM) {
		t.Error("escrowed key differs from what was uploaded")
	}

	if _, err := e.client.Issue(ctx, model.IssueRequest{Env: "prod", CSR: string(csr)}); !isStatus(err, 403) {
		t.Errorf("developer issued prod over http: %v", err)
	}
	if _, err := e.client.Audit(ctx, ""); !isStatus(err, 403) {
		t.Errorf("developer read audit log: %v", err)
	}

	// An identity with no binding at all is turned away at the door.
	e.sts.SetARN("arn:aws:sts::111111111111:assumed-role/RandomRole/mallory")
	if _, err := e.client.WhoAmI(ctx); !isStatus(err, 403) {
		t.Errorf("unbound role got in: %v", err)
	}
}

func isStatus(err error, status int) bool {
	ae, ok := err.(*client.APIError)
	return ok && ae.Status == status
}

// writeScript creates a stand-in for the flash script. It checks it got
// everything it needs and records the device it "flashed".
func writeScript(t *testing.T, dir string, fail bool) (script, record string) {
	t.Helper()
	record = filepath.Join(dir, "flashed.txt")
	exit := "0"
	if fail {
		exit = "1"
	}
	body := `#!/bin/sh
set -eu
for v in "$ADL_DEVICE_KEY" "$ADL_DEVICE_CERT" "$ADL_DEVICE_CHAIN" "$ADL_CA_CHAIN" "$ADL_CA_ROOT"; do
  test -s "$v" || { echo "missing $v"; exit 2; }
done
grep -q "PRIVATE KEY" "$ADL_DEVICE_KEY"
echo "$ADL_DEVICE_ID $ADL_SERIAL $ADL_CHIP_MAC $ADL_WORK_DIR" >> "` + record + `"
exit ` + exit + "\n"
	script = filepath.Join(dir, "flash.sh")
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, record
}

func TestEndOfLine(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.sts.SetARN(stationARN)
	dir := t.TempDir()
	good, record := writeScript(t, dir, false)
	badDir := t.TempDir()
	bad, _ := writeScript(t, badDir, true)

	mac := "f412fa0a0b0c"
	st := &eol.Station{
		Client: e.client, Env: "prod", Name: "line-1", Port: "/dev/null", FlashScript: good,
		Firmware: "1.0.0", KeyType: "rsa2048", LogPath: filepath.Join(dir, "eol.csv"),
		ReadMAC: func(context.Context) (string, error) { return mac, nil },
	}
	if err := st.Preflight(ctx); err != nil {
		t.Fatal(err)
	}

	res, err := st.Provision(ctx, eol.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := e.client.GetDevice(ctx, res.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Device.Status != model.DeviceProvisioned || dev.Device.ChipID != mac || dev.Device.Station != "line-1" {
		t.Errorf("device after EoL: %+v", dev.Device)
	}
	if len(dev.Certificates) != 1 || dev.Certificates[0].KeyEscrowed {
		t.Errorf("prod cert should exist and must not be escrowed: %+v", dev.Certificates)
	}
	rec, _ := os.ReadFile(record)
	workDir := strings.Fields(string(rec))[3]
	if _, err := os.Stat(workDir); !os.IsNotExist(err) {
		t.Errorf("work dir %s with the private key was not wiped", workDir)
	}

	// Same board on the line again: refuse.
	if _, err := st.Provision(ctx, eol.Options{}); err == nil || !strings.Contains(err.Error(), "already provisioned") {
		t.Errorf("re-running a provisioned board: %v", err)
	}

	// New board, flash fails half way.
	mac = "f412fa0a0b0d"
	st.FlashScript = bad
	if _, err := st.Provision(ctx, eol.Options{}); err == nil {
		t.Fatal("expected flash failure")
	}
	list, _ := e.client.ListDevices(ctx, "prod")
	var stuck model.Device
	for _, d := range list.Devices {
		if d.ChipID == mac {
			stuck = d
		}
	}
	if stuck.Status != model.DeviceIssued {
		t.Fatalf("failed board should be left issued, got %+v", stuck)
	}

	// Operator fixes the cable and re-runs: same identity, new key.
	st.FlashScript = good
	res2, err := st.Provision(ctx, eol.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res2.DeviceID != stuck.ID || !res2.Reissued {
		t.Errorf("expected re-issue of %s, got %+v", stuck.ID, res2)
	}
	d2, _ := e.client.GetDevice(ctx, stuck.ID)
	if d2.Device.Status != model.DeviceProvisioned || len(d2.Certificates) != 2 || d2.Certificates[0].Status != model.CertRevoked {
		t.Errorf("after retry: %+v", d2)
	}

	logData, _ := os.ReadFile(st.LogPath)
	if got := strings.Count(string(logData), "\n"); got != 3 {
		t.Errorf("expected 3 station log lines, got %d:\n%s", got, logData)
	}

	// An admin can see all of it in the audit log.
	e.sts.SetARN(adminARN)
	audit, err := e.client.Audit(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var provisioned int
	for _, ev := range audit.Events {
		if ev.Action == "device.provisioned" {
			provisioned++
		}
	}
	if provisioned != 2 {
		t.Errorf("expected 2 provisioned audit events, got %d", provisioned)
	}
	crl, err := e.client.CRL(ctx, "prod")
	if err != nil || len(crl) == 0 {
		t.Errorf("crl: %v", err)
	}
}

// The default station path: identity written into the adl_certs NVS
// partition, no flash script.
func TestEndOfLineNVS(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.sts.SetARN(stationARN)
	board := espflashtest.NewBoard(t, espflashtest.EncodeTable(espflashtest.ADLTable))

	mac := "f412fa0a0c01"
	st := &eol.Station{
		Client: e.client, Env: "prod", Name: "line-1", Port: "/dev/null", Esptool: board.Esptool,
		NVS:      &espflash.NVS{Generator: espflashtest.Generator(t)},
		Firmware: "1.0.0", KeyType: "rsa2048",
		ReadMAC: func(context.Context) (string, error) { return mac, nil },
	}
	if err := st.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := st.Provision(ctx, eol.Options{})
	if err != nil {
		t.Fatal(err)
	}

	img, offset := board.Image(t)
	if offset != "0x120000" {
		t.Errorf("identity written at %s, want adl_certs at 0x120000", offset)
	}
	// In a real NVS image each value sits after a binary entry header, not
	// a newline, so decode from every BEGIN marker rather than chaining
	// pem.Decode.
	var certs []*x509.Certificate
	var key crypto.Signer
	for _, part := range bytes.Split(img, []byte("-----BEGIN "))[1:] {
		block, _ := pem.Decode(append([]byte("-----BEGIN "), part...))
		if block == nil {
			t.Fatal("unparseable PEM in the NVS image")
		}
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			certs = append(certs, c)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			key = k.(crypto.Signer)
		}
	}
	if key == nil || len(certs) == 0 {
		t.Fatalf("image holds %d certs and key=%v", len(certs), key != nil)
	}
	leaf := certs[0]
	if leaf.Subject.CommonName != res.DeviceID {
		t.Errorf("first cert in NVS is %s, want %s", leaf.Subject.CommonName, res.DeviceID)
	}
	if !leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()) {
		t.Error("key in NVS does not match the certificate")
	}
	if !certs[len(certs)-1].Equal(e.stack.Roots["prod"]) {
		t.Error("ca_root in NVS is not the prod root")
	}

	// A board with today's firmware (no adl_certs partition) is refused before
	// anything is written, and stays unconfirmed for a re-run.
	mac = "f412fa0a0c02"
	old := espflashtest.NewBoard(t, espflashtest.EncodeTable(espflashtest.ADLTable[:4]))
	st.Esptool = old.Esptool
	if _, err := st.Provision(ctx, eol.Options{}); err == nil || !strings.Contains(err.Error(), "adl_certs, data, nvs") {
		t.Fatalf("board without adl_certs: %v", err)
	}
	if _, err := os.Stat(old.Written); err == nil {
		t.Error("something was written to a board without adl_certs")
	}
}
