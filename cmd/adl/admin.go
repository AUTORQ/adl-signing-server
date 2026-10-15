package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/edge-labs/adl-signing-server/internal/client"
	"github.com/edge-labs/adl-signing-server/internal/eol"
	"github.com/edge-labs/adl-signing-server/internal/model"
	"github.com/edge-labs/adl-signing-server/internal/pki"
)

func cmdCA(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: adl ca status|csr|install|crl --env ENV")
	}
	sub, args := args[0], args[1:]
	fset := flag.NewFlagSet("ca "+sub, flag.ExitOnError)
	env := fset.String("env", "", "stage (dev, prod) or full environment name")
	partner := fset.String("partner", defaultPartner(), "partner whose intermediate this is")
	out := fset.String("out", "", "write output to this file")
	var cn, org, ou, country, chainFile *string
	switch sub {
	case "csr":
		cn = fset.String("cn", "", "common name, e.g. \"EDGE Labs Intermediate CA prod\"")
		org = fset.String("org", "", "organization (the partner's name)")
		ou = fset.String("ou", "IoT Devices", "organizational unit")
		country = fset.String("country", "US", "country")
	case "install":
		chainFile = fset.String("chain", "", "PEM file: signed intermediate first, then up to and including the root")
	}
	_ = fset.Parse(args)
	if *env == "" {
		return errors.New("--env is required")
	}
	c, err := newClient(ctx, *env)
	if err != nil {
		return err
	}
	if *env, err = resolveEnv(ctx, c, *partner, *env); err != nil {
		return err
	}
	switch sub {
	case "status":
		st, err := c.CAStatus(ctx, *env)
		if err != nil {
			return err
		}
		fmt.Printf("env          %s\nconfigured   %v\nkms key      %s sha256:%s\n", st.Env, st.Configured, st.KeyAlgorithm, st.PublicKeySHA256)
		if st.Configured {
			fmt.Printf("subject      %s\nissuer       %s\nvalid        %s .. %s\nfingerprint  %s\n",
				st.Subject, st.Issuer, st.NotBefore.Format("2006-01-02"), st.NotAfter.Format("2006-01-02"), st.FingerprintSHA256)
			if d := time.Until(st.NotAfter); d < 365*24*time.Hour {
				fmt.Printf("WARNING      intermediate expires in %d days, plan the rotation\n", int(d.Hours()/24))
			}
		}
		if *out != "" && st.ChainPEM != "" {
			return os.WriteFile(*out, []byte(st.ChainPEM), 0o644)
		}
		return nil
	case "csr":
		if *cn == "" || *org == "" {
			return errors.New("--cn and --org are required")
		}
		r, err := c.CACSR(ctx, *env, model.CACSRRequest{CommonName: *cn, Organization: *org, OrganizationalUnit: *ou, Country: *country})
		if err != nil {
			return err
		}
		return writeOrPrint(*out, []byte(r.CSRPEM))
	case "install":
		if *chainFile == "" {
			return errors.New("--chain is required")
		}
		data, err := os.ReadFile(*chainFile)
		if err != nil {
			return err
		}
		st, err := c.CAInstall(ctx, *env, model.CAInstallRequest{ChainPEM: string(data)})
		if err != nil {
			return err
		}
		fmt.Printf("installed %s CA\n  subject     %s\n  issuer      %s\n  expires     %s\n  fingerprint %s\n",
			st.Env, st.Subject, st.Issuer, st.NotAfter.Format("2006-01-02"), st.FingerprintSHA256)
		return nil
	case "crl":
		der, err := c.CRL(ctx, *env)
		if err != nil {
			return err
		}
		if *out == "" {
			return errors.New("--out is required (the CRL is binary DER)")
		}
		return os.WriteFile(*out, der, 0o644)
	}
	return fmt.Errorf("unknown ca command %q", sub)
}

func writeOrPrint(path string, data []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", path)
	return nil
}

var legacyCertRE = regexp.MustCompile(`^device-([A-Za-z0-9_-]+)\.crt$`)

// cmdImport walks a copy of the old droplet's key directory and registers
// every device certificate in it.
func cmdImport(ctx context.Context, args []string) error {
	fset := flag.NewFlagSet("import", flag.ExitOnError)
	env := fset.String("env", "", "stage or environment the certs belong to")
	partner := fset.String("partner", defaultPartner(), "partner the certs belong to")
	dir := fset.String("dir", "", "directory to scan (e.g. a copy of dev-keys/device)")
	withKeys := fset.Bool("with-keys", false, "also escrow device-<ID>.key files (only allowed where escrow is on)")
	provisioned := fset.Bool("provisioned", false, "mark imported devices as provisioned (they are already in the field)")
	dryRun := fset.Bool("dry-run", false, "show what would be imported")
	_ = fset.Parse(args)
	if *env == "" || *dir == "" {
		return errors.New("--env and --dir are required")
	}

	type found struct{ cert, key, chain string }
	byID := map[string]*found{}
	err := filepath.WalkDir(*dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		m := legacyCertRE.FindStringSubmatch(d.Name())
		if m == nil {
			return nil
		}
		id := m[1]
		if byID[id] != nil {
			return nil // bundles/ and device/ hold copies of the same files
		}
		f := &found{cert: p}
		base := filepath.Dir(p)
		if _, err := os.Stat(filepath.Join(base, "device-"+id+".key")); err == nil {
			f.key = filepath.Join(base, "device-"+id+".key")
		}
		if _, err := os.Stat(filepath.Join(base, "device-"+id+"-chain.pem")); err == nil {
			f.chain = filepath.Join(base, "device-"+id+"-chain.pem")
		}
		byID[id] = f
		return nil
	})
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return fmt.Errorf("no device-<ID>.crt files under %s", *dir)
	}

	var c *client.Client
	if !*dryRun {
		if c, err = newClient(ctx, *env); err != nil {
			return err
		}
		if *env, err = resolveEnv(ctx, c, *partner, *env); err != nil {
			return err
		}
	}
	var ok, skipped, failed int
	for _, id := range ids {
		f := byID[id]
		certPEM, err := os.ReadFile(f.cert)
		if err != nil {
			return err
		}
		req := model.ImportRequest{Env: *env, CertificatePEM: string(certPEM), Provisioned: *provisioned}
		if f.chain != "" {
			// The legacy chain file is leaf + intermediate; we want the
			// issuer part only.
			data, _ := os.ReadFile(f.chain)
			if certs, err := pki.ParseCertificates(data); err == nil && len(certs) > 1 {
				req.ChainPEM = string(pki.EncodeCertificates(certs[1:]...))
			}
		}
		if *withKeys && f.key != "" {
			data, _ := os.ReadFile(f.key)
			req.PrivateKeyPEM = string(data)
		}
		if *dryRun {
			fmt.Printf("would import %-12s key=%v chain=%v\n", id, req.PrivateKeyPEM != "", req.ChainPEM != "")
			continue
		}
		_, err = c.Import(ctx, req)
		switch {
		case err == nil:
			ok++
			fmt.Printf("imported %s\n", id)
		case isCode(err, "already_imported"):
			skipped++
			fmt.Printf("skipped  %s (already registered)\n", id)
		default:
			failed++
			fmt.Printf("FAILED   %s: %v\n", id, err)
		}
	}
	if !*dryRun {
		fmt.Printf("\n%d imported, %d already there, %d failed\n", ok, skipped, failed)
		if failed > 0 {
			return errors.New("some imports failed")
		}
	}
	return nil
}

func isCode(err error, code string) bool {
	_, ok := client.IsCode(err, code)
	return ok
}

func cmdEOL(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: adl eol check|provision --station NAME --port PORT")
	}
	sub, args := args[0], args[1:]
	fset := flag.NewFlagSet("eol "+sub, flag.ExitOnError)
	env := fset.String("env", "prod", "stage (dev, prod) or environment to provision into")
	partner := fset.String("partner", defaultPartner(), "partner to act for, if you may act for several")
	move := fset.Bool("move", false, "boards already in another stage are assigned here (revokes their certificates there)")
	station := fset.String("station", os.Getenv("ADL_STATION"), "station name, recorded against every device (env ADL_STATION)")
	port := fset.String("port", os.Getenv("ADL_PORT"), "serial port of the board, e.g. /dev/ttyUSB0 (env ADL_PORT)")
	chip := fset.String("chip", "esp32s3", "esptool chip type")
	esptool := fset.String("esptool", envOr("ADL_ESPTOOL", "esptool.py"), "esptool command")
	flashScript := fset.String("flash-script", envOr("ADL_FLASH_SCRIPT", defaultScript("flash-esp32s3.sh")), "script that writes the credentials to the board")
	verifyScript := fset.String("verify-script", os.Getenv("ADL_VERIFY_SCRIPT"), "optional script run after flashing")
	firmware := fset.String("firmware", os.Getenv("ADL_FIRMWARE_VERSION"), "firmware version on the line, recorded with the device")
	keyType := fset.String("key-type", "rsa2048", "rsa2048 (needed for the ESP32-S3 DS peripheral) or ecdsa-p256")
	logPath := fset.String("log", defaultLogPath(), "CSV log of every board this station touched")
	reissue := fset.Bool("reissue", false, "re-key a board that is already provisioned (needs revoke permission)")
	id := fset.String("id", "", "force a device id instead of allocating one")
	loop := fset.Bool("loop", false, "keep going: provision, then wait for the next board")
	_ = fset.Parse(args)

	c, err := newClient(ctx, *env)
	if err != nil {
		return err
	}
	if *env, err = resolveEnv(ctx, c, *partner, *env); err != nil {
		return err
	}
	st := &eol.Station{
		Client: c, Env: *env, Name: *station, Port: *port, Chip: *chip, Esptool: *esptool,
		FlashScript: *flashScript, VerifyScript: *verifyScript, Firmware: *firmware,
		KeyType: *keyType, LogPath: *logPath, Out: os.Stdout,
	}
	switch sub {
	case "check":
		if err := st.Preflight(ctx); err != nil {
			return err
		}
		fmt.Println("station ready")
		return nil
	case "provision":
		if *port == "" {
			return errors.New("--port is required")
		}
		if err := st.Preflight(ctx); err != nil {
			return err
		}
		in := bufio.NewReader(os.Stdin)
		for {
			res, err := st.Provision(ctx, eol.Options{DeviceID: *id, Reissue: *reissue, Move: *move})
			if err != nil {
				banner("FAIL", err.Error())
			} else {
				msg := fmt.Sprintf("%s  serial %s  chip %s", res.DeviceID, res.Serial, res.ChipID)
				if res.Reissued {
					msg += "  (re-issued)"
				}
				banner("PASS", msg)
			}
			if !*loop {
				return err
			}
			fmt.Print("\nconnect the next board and press Enter (Ctrl-C to stop) ")
			if _, rerr := in.ReadString('\n'); rerr != nil {
				return nil
			}
			*id = ""
		}
	}
	return fmt.Errorf("unknown eol command %q", sub)
}

func banner(status, msg string) {
	line := strings.Repeat("=", 60)
	fmt.Printf("\n%s\n  %s  %s\n%s\n", line, status, msg, line)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// defaultScript looks for the bundled script next to the binary, then in
// the repo layout.
func defaultScript(name string) string {
	if exe, err := os.Executable(); err == nil {
		for _, p := range []string{
			filepath.Join(filepath.Dir(exe), name),
			filepath.Join(filepath.Dir(exe), "..", "share", "adl", name),
		} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return filepath.Join("scripts", "eol", name)
}

func defaultLogPath() string {
	if dir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(dir, ".local", "state", "adl", "eol-log.csv")
	}
	return "eol-log.csv"
}
