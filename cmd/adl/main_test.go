package main

import (
	"bytes"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/AUTORQ/adl-signing-server/internal/auth"
	"github.com/AUTORQ/adl-signing-server/internal/client"
	"github.com/AUTORQ/adl-signing-server/internal/localstack"
	"github.com/AUTORQ/adl-signing-server/internal/pki"
)

func runAdl(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader(""))
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

// Every positional argument and every flag that takes a value must
// complete. Walks the whole tree so a new command can't skip it.
func TestEverythingCompletes(t *testing.T) {
	root := newRootCommand()
	root.InitDefaultCompletionCmd()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		path := c.CommandPath()
		if c.Runnable() && c.Args != nil && c.ValidArgsFunction == nil && len(c.ValidArgs) == 0 && !takesNoArgs(c) {
			t.Errorf("%s takes arguments but has no completion", path)
		}
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Value.Type() == "bool" || f.Name == "help" {
				return
			}
			if _, ok := c.GetFlagCompletionFunc(f.Name); !ok {
				t.Errorf("%s --%s has no completion", path, f.Name)
			}
		})
		for _, sub := range c.Commands() {
			if sub.Name() == "completion" && c == root {
				continue // cobra's own script generator
			}
			walk(sub)
		}
	}
	walk(root)
}

func takesNoArgs(c *cobra.Command) bool {
	return c.Args(c, []string{"x"}) != nil
}

func TestHelpForFlashing(t *testing.T) {
	out, err := runAdl(t, "eol", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ONE-TIME STATION SETUP", "EVERY SHIFT", "WHEN A BOARD FAILS", "adl eol check", "ADL_STATION"} {
		if !strings.Contains(out, want) {
			t.Errorf("adl eol --help is missing %q", want)
		}
	}
	out, _ = runAdl(t, "eol", "provision", "--help")
	if !strings.Contains(out, "FLASH SCRIPT CONTRACT") || !strings.Contains(out, "ADL_CA_ROOT") {
		t.Errorf("provision help lacks the script contract:\n%s", out)
	}
}

func TestInstallWords(t *testing.T) {
	bin := t.TempDir()
	out, err := runAdl(t, "install", "cli", "local", "--bin-dir", bin)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(bin, "adl")); err != nil {
		t.Fatal("adl not installed under its own name")
	}
	comp := t.TempDir()
	if out, err := runAdl(t, "install", "completion", "local", "--shell", "fish", "--completion-dir", comp); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(comp, "adl.fish")); err != nil {
		t.Fatal("fish completion not written as adl.fish")
	}
}

// Mint, lose the files, fetch them back, and pull the CA certs, all
// against the in-memory server.
func TestMintFetchAndPull(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := localstack.New(log)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(st.Handler(&auth.Local{Permissions: []string{"*"}}, log))
	defer srv.Close()
	t.Setenv("ADL_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	for _, k := range []string{"ADL_URL", "ADL_REGION", "ADL_AUDIENCE", "ADL_PROFILE", "ADL_PARTNER"} {
		t.Setenv(k, "")
	}
	if out, err := runAdl(t, "configure", "--url", srv.URL, "--local"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}

	certs := t.TempDir()
	out, err := runAdl(t, "mint", "--out", certs, "--label", "board=rev-c")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	id := strings.Fields(strings.TrimPrefix(out, "minted "))[0]
	dir := filepath.Join(certs, id, "device")
	key, _ := os.ReadFile(filepath.Join(dir, "device-"+id+".key"))
	root := mustRoot(t, filepath.Join(dir, "ca-root.pem"))
	if !root.Equal(st.Roots["dev"]) {
		t.Error("ca-root.pem is not the dev root")
	}

	if err := os.RemoveAll(certs); err != nil {
		t.Fatal(err)
	}
	if out, err := runAdl(t, "fetch", id, "--out", certs); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	back, _ := os.ReadFile(filepath.Join(dir, "device-"+id+".key"))
	if len(key) == 0 || !bytes.Equal(key, back) {
		t.Error("fetch did not bring back the same private key")
	}
	for _, f := range []string{".crt", "-chain.pem"} {
		if _, err := os.Stat(filepath.Join(dir, "device-"+id+f)); err != nil {
			t.Errorf("fetch missing device-%s%s", id, f)
		}
	}
	if !mustRoot(t, filepath.Join(dir, "ca-root.pem")).Equal(root) {
		t.Error("fetched root differs")
	}

	pulled := t.TempDir()
	if out, err := runAdl(t, "ca", "pull", "--stage", "prod", "--out", pulled); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !mustRoot(t, filepath.Join(pulled, "prod-root.pem")).Equal(st.Roots["prod"]) {
		t.Error("ca pull wrote the wrong prod root")
	}
	for _, f := range []string{"prod-intermediate.pem", "prod-ca-chain.pem"} {
		if _, err := os.Stat(filepath.Join(pulled, f)); err != nil {
			t.Errorf("ca pull missing %s", f)
		}
	}
}

func mustRoot(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := pki.ParseCertificates(data)
	if err != nil || len(certs) != 1 || !isSelfSigned(certs[0]) {
		t.Fatalf("%s is not a single self signed root: %v", path, err)
	}
	return certs[0]
}

// --env, the spelling from before partners, still works wherever --stage
// does, including where a stage is required.
func TestEnvIsStillAccepted(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := localstack.New(log)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(st.Handler(&auth.Local{Permissions: []string{"*"}}, log))
	defer srv.Close()
	t.Setenv("ADL_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	for _, k := range []string{"ADL_URL", "ADL_REGION", "ADL_AUDIENCE", "ADL_PROFILE", "ADL_PARTNER"} {
		t.Setenv(k, "")
	}
	if out, err := runAdl(t, "configure", "--url", srv.URL, "--local"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := runAdl(t, "ca", "status", "--env", "dev"); err != nil || !strings.Contains(out, "configured   true") {
		t.Fatalf("ca status --env dev: %v\n%s", err, out)
	}
	if _, err := runAdl(t, "ca", "status"); err == nil || !strings.Contains(err.Error(), "--stage is required") {
		t.Fatalf("ca status without a stage: %v", err)
	}
}

// configure --stage edits that stage's server and keeps the rest.
func TestConfigurePerStage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("ADL_CONFIG", path)
	for _, k := range []string{"ADL_URL", "ADL_REGION", "ADL_AUDIENCE", "ADL_PROFILE", "ADL_PARTNER"} {
		t.Setenv(k, "")
	}
	for _, args := range [][]string{
		{"configure", "--stage", "dev", "--url", "https://dev.example", "--region", "us-east-1", "--audience", "a:dev", "--profile", "p-dev"},
		{"configure", "--stage", "prod", "--url", "https://prod.example", "--region", "us-east-1", "--audience", "a:prod"},
		{"configure", "--stage", "prod", "--profile", "p-prod"},
		{"configure", "--stage", "prod", "--partner", "globex"},
	} {
		if out, err := runAdl(t, args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	dev, prod := cfg.Stages["dev"], cfg.Stages["prod"]
	if dev == nil || dev.URL != "https://dev.example" || dev.Profile != "p-dev" {
		t.Errorf("dev server: %+v", dev)
	}
	if prod == nil || prod.URL != "https://prod.example" || prod.Audience != "a:prod" || prod.Profile != "p-prod" {
		t.Errorf("prod server: %+v", prod)
	}
	if cfg.Partner != "globex" {
		t.Errorf("default partner %q", cfg.Partner)
	}
}
