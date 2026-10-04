package main

import (
	"archive/zip"
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/edge-labs/adl-signing-server/internal/client"
	"github.com/edge-labs/adl-signing-server/internal/model"
	"github.com/edge-labs/adl-signing-server/internal/pki"
)

func cmdConfigure(args []string) error {
	fs := flag.NewFlagSet("configure", flag.ExitOnError)
	cfg := &client.Config{}
	if existing, err := client.LoadConfig(); err == nil {
		cfg = existing
	}
	fs.StringVar(&cfg.URL, "url", cfg.URL, "signing server URL (https://...)")
	fs.StringVar(&cfg.Region, "region", cfg.Region, "AWS region the server runs in")
	fs.StringVar(&cfg.Audience, "audience", cfg.Audience, "server audience string (from the Terraform outputs)")
	fs.StringVar(&cfg.Profile, "profile", cfg.Profile, "AWS profile to use (e.g. your SSO profile)")
	fs.BoolVar(&cfg.Local, "local", cfg.Local, "talk to a local `adl-signer serve -local-insecure`")
	_ = fs.Parse(args)
	if cfg.URL == "" {
		return errors.New("--url is required")
	}
	if !cfg.Local && (cfg.Region == "" || cfg.Audience == "") {
		return errors.New("--region and --audience are required (or --local)")
	}
	path, err := cfg.Save()
	if err != nil {
		return err
	}
	fmt.Printf("saved %s\n", path)
	return nil
}

func cmdWhoami(ctx context.Context, _ []string) error {
	c, err := newClient(ctx)
	if err != nil {
		return err
	}
	w, err := c.WhoAmI(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("principal:   %s\narn:         %s\npermissions: %s\n", w.Principal, w.ARN, strings.Join(w.Permissions, " "))
	return nil
}

// cmdMint is the developer happy path: one command, cert on disk, key
// backed up on the server.
func cmdMint(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	env := fs.String("env", "dev", "environment")
	id := fs.String("id", "", "device id (default: next free DVTADL number)")
	out := fs.String("out", "certs", "output directory")
	keyType := fs.String("key-type", "rsa2048", "rsa2048 or ecdsa-p256")
	noEscrow := fs.Bool("no-escrow", false, "do not back up the private key on the server")
	zipIt := fs.Bool("zip", false, "also write <ID>.zip like the old bundles")
	replace := fs.Bool("replace", false, "re-issue an existing device id (revokes its current cert)")
	lbl := labels{}
	fs.Var(lbl, "label", "key=value label, repeatable (e.g. --label board=rev-c --label owner=jane)")
	_ = fs.Parse(args)

	c, err := newClient(ctx)
	if err != nil {
		return err
	}
	key, err := pki.GenerateKey(*keyType)
	if err != nil {
		return err
	}
	csr, err := pki.CreateCSR(key, pkix.Name{CommonName: *id})
	if err != nil {
		return err
	}
	keyPEM, err := pki.EncodePrivateKey(key)
	if err != nil {
		return err
	}
	req := model.IssueRequest{Env: *env, DeviceID: *id, CSR: string(csr), Labels: lbl, Replace: *replace}
	if !*noEscrow {
		req.PrivateKey = string(keyPEM)
	}
	resp, err := c.Issue(ctx, req)
	if err != nil {
		return err
	}
	b := &model.Bundle{DeviceID: resp.Device.ID, Env: resp.Device.Env, Serial: resp.Certificate.Serial,
		CertificatePEM: resp.CertificatePEM, ChainPEM: resp.ChainPEM, PrivateKeyPEM: string(keyPEM)}
	dir, err := writeBundle(*out, b, *zipIt)
	if err != nil {
		return fmt.Errorf("certificate %s was issued but writing files failed (recover with `adl fetch %s`): %w", b.DeviceID, b.DeviceID, err)
	}
	fmt.Printf("minted %s (%s)\n  serial   %s\n  expires  %s\n  files    %s\n",
		b.DeviceID, b.Env, b.Serial, resp.Certificate.NotAfter.Format("2006-01-02"), dir)
	if resp.Certificate.KeyEscrowed {
		fmt.Printf("  backup   private key escrowed; `adl fetch %s` gets everything back\n", b.DeviceID)
	} else {
		fmt.Printf("  backup   key NOT escrowed - if you lose %s it is gone\n", filepath.Join(dir, "device-"+b.DeviceID+".key"))
	}
	return nil
}

func cmdFetch(ctx context.Context, args []string) error {
	flags, pos := splitArgs(args, "no-key", "zip")
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	out := fs.String("out", "certs", "output directory")
	serial := fs.String("serial", "", "a specific certificate (default: current)")
	noKey := fs.Bool("no-key", false, "skip the escrowed private key")
	zipIt := fs.Bool("zip", false, "also write <ID>.zip")
	_ = fs.Parse(flags)
	if len(pos) != 1 {
		return errors.New("usage: adl fetch DEVICE_ID [--out DIR]")
	}
	c, err := newClient(ctx)
	if err != nil {
		return err
	}
	b, err := c.Bundle(ctx, pos[0], *serial, !*noKey)
	if ae, ok := client.IsCode(err, "not_found"); ok && !*noKey && strings.Contains(ae.Message, "escrowed") {
		fmt.Fprintln(os.Stderr, "note: no escrowed key for this certificate, fetching certificate only")
		b, err = c.Bundle(ctx, pos[0], *serial, false)
	}
	if err != nil {
		return err
	}
	dir, err := writeBundle(*out, b, *zipIt)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s (serial %s) to %s\n", b.DeviceID, b.Serial, dir)
	return nil
}

// writeBundle lays files out like the old droplet bundles so existing
// flashing scripts keep working:
//
//	<out>/<ID>/device/device-<ID>.crt        leaf
//	<out>/<ID>/device/device-<ID>-chain.pem  leaf + intermediate
//	<out>/<ID>/device/device-<ID>.key        private key (0600)
//	<out>/<ID>/device/ca-chain.pem           intermediate + root
func writeBundle(out string, b *model.Bundle, zipIt bool) (string, error) {
	dir := filepath.Join(out, b.DeviceID, "device")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	leaf, err := pki.ParseCertificates([]byte(b.CertificatePEM))
	if err != nil {
		return "", err
	}
	files := map[string][]byte{
		"device-" + b.DeviceID + ".crt": []byte(b.CertificatePEM),
	}
	if b.ChainPEM != "" {
		chain, err := pki.ParseCertificates([]byte(b.ChainPEM))
		if err != nil {
			return "", err
		}
		files["device-"+b.DeviceID+"-chain.pem"] = pki.EncodeCertificates(leaf[0], chain[0])
		files["ca-chain.pem"] = []byte(b.ChainPEM)
	}
	if b.PrivateKeyPEM != "" {
		files["device-"+b.DeviceID+".key"] = []byte(b.PrivateKeyPEM)
	}
	for name, data := range files {
		mode := os.FileMode(0o644)
		if strings.HasSuffix(name, ".key") {
			mode = 0o600
		}
		p := filepath.Join(dir, name)
		if existing, err := os.ReadFile(p); err == nil && string(existing) != string(data) {
			// Never silently clobber a different key/cert.
			backup := p + ".old-" + time.Now().Format("20060102150405")
			if err := os.Rename(p, backup); err != nil {
				return "", err
			}
			fmt.Fprintf(os.Stderr, "moved existing %s to %s\n", p, backup)
		}
		if err := os.WriteFile(p, data, mode); err != nil {
			return "", err
		}
	}
	meta, _ := json.MarshalIndent(map[string]string{"device_id": b.DeviceID, "env": b.Env, "serial": b.Serial}, "", "  ")
	_ = os.WriteFile(filepath.Join(out, b.DeviceID, "bundle.json"), append(meta, '\n'), 0o644)
	if zipIt {
		if err := zipDir(filepath.Join(out, b.DeviceID+".zip"), filepath.Join(out, b.DeviceID)); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func zipDir(dst, src string) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	base := filepath.Dir(src)
	err = filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(base, p)
		w, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	})
	if err != nil {
		return err
	}
	return zw.Close()
}

func cmdList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	env := fs.String("env", "", "only this environment")
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)
	c, err := newClient(ctx)
	if err != nil {
		return err
	}
	l, err := c.ListDevices(ctx, *env)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(l)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DEVICE\tENV\tSTATUS\tOWNER\tCHIP\tCREATED")
	for _, d := range l.Devices {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", d.ID, d.Env, d.Status, d.Owner, dash(d.ChipID), d.CreatedAt.Format("2006-01-02"))
	}
	return tw.Flush()
}

func cmdShow(ctx context.Context, args []string) error {
	flags, pos := splitArgs(args, "json")
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(flags)
	if len(pos) != 1 {
		return errors.New("usage: adl show DEVICE_ID")
	}
	c, err := newClient(ctx)
	if err != nil {
		return err
	}
	d, err := c.GetDevice(ctx, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(d)
	}
	dev := d.Device
	fmt.Printf("device   %s (%s)\nstatus   %s\nowner    %s\nchip     %s\ncreated  %s\n",
		dev.ID, dev.Env, dev.Status, dev.Owner, dash(dev.ChipID), dev.CreatedAt.Format(time.RFC3339))
	if dev.ProvisionedAt != nil {
		fmt.Printf("flashed  %s by %s on %s (fw %s)\n", dev.ProvisionedAt.Format(time.RFC3339), dev.ProvisionedBy, dev.Station, dash(dev.FirmwareVersion))
	}
	for k, v := range dev.Labels {
		fmt.Printf("label    %s=%s\n", k, v)
	}
	fmt.Println("\ncertificates:")
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  SERIAL\tSTATUS\tISSUED\tEXPIRES\tKEY\tESCROWED\tCURRENT")
	for _, c := range d.Certificates {
		st := string(c.Status)
		if c.RevocationReason != "" {
			st += " (" + c.RevocationReason + ")"
		}
		cur := ""
		if c.Serial == dev.CurrentSerial {
			cur = "*"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%v\t%s\n", c.Serial, st, c.IssuedAt.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"), c.KeyAlgorithm, c.KeyEscrowed, cur)
	}
	return tw.Flush()
}

func cmdRevoke(ctx context.Context, args []string) error {
	flags, pos := splitArgs(args, "yes")
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	reason := fs.String("reason", "", "keyCompromise, superseded, cessationOfOperation, affiliationChanged or unspecified")
	serial := fs.String("serial", "", "only this certificate (default: all active certs of the device)")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	_ = fs.Parse(flags)
	if len(pos) != 1 || *reason == "" {
		return errors.New("usage: adl revoke DEVICE_ID --reason REASON")
	}
	if !*yes && !confirm(fmt.Sprintf("Revoke %s (%s)? This cannot be undone.", pos[0], *reason)) {
		return errors.New("aborted")
	}
	c, err := newClient(ctx)
	if err != nil {
		return err
	}
	d, err := c.Revoke(ctx, pos[0], model.RevokeRequest{Serial: *serial, Reason: *reason})
	if err != nil {
		return err
	}
	fmt.Printf("%s is now %s\n", d.Device.ID, d.Device.Status)
	return nil
}

func cmdAudit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	day := fs.String("day", "", "UTC day YYYY-MM-DD (default today)")
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)
	c, err := newClient(ctx)
	if err != nil {
		return err
	}
	l, err := c.Audit(ctx, *day)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(l)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tACTOR\tACTION\tENV\tDEVICE\tSERIAL")
	for _, e := range l.Events {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.Time.Format(time.TimeOnly), e.Actor, e.Action, dash(e.Env), dash(e.DeviceID), dash(e.Serial))
	}
	return tw.Flush()
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func confirm(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	var ans string
	_, _ = fmt.Scanln(&ans)
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes"
}
