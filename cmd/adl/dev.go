package main

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/AUTORQ/adl-signing-server/internal/client"
	"github.com/AUTORQ/adl-signing-server/internal/eol"
	"github.com/AUTORQ/adl-signing-server/internal/model"
	"github.com/AUTORQ/adl-signing-server/internal/pki"
)

func newConfigureCommand() *cobra.Command {
	root := &client.Config{}
	if existing, err := client.LoadConfig(); err == nil {
		root = existing
	}
	// Flags land in `in`; only the ones given overwrite the saved server,
	// which is the default one or, with --stage, that stage's.
	var (
		in      client.Server
		stage   string
		partner string
	)
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Point adl at the signing server",
		Long: `Point adl at the signing server. The values come from the Terraform output
"cli_configure". Flags you leave out keep their saved value.

With a signer per stage, configure each one with --stage; --stage then picks
the server for every other command. --partner sets the partner to act for
by default, for people who may act for several.

The config is adl/config.json in your user config directory (~/.config on
Linux, ~/Library/Application Support on macOS, %AppData% on Windows), or
$ADL_CONFIG. ADL_URL, ADL_REGION, ADL_AUDIENCE, ADL_PROFILE and ADL_PARTNER
override it.`,
		Example: `  adl configure --url https://signer.example --region us-east-1 \
                --audience adl-signing-server:123456789012 --profile my-sso
  adl configure --stage prod --url https://signer.prod.example --region us-east-1 \
                --audience adl-signing-server:210987654321 --profile my-prod
  adl configure --url http://127.0.0.1:8080 --local`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := &root.Server
			if stage != "" {
				if root.Stages == nil {
					root.Stages = map[string]*client.Server{}
				}
				if root.Stages[stage] == nil {
					root.Stages[stage] = &client.Server{}
				}
				cfg = root.Stages[stage]
			}
			f := cmd.Flags()
			for name, apply := range map[string]func(){
				"url":      func() { cfg.URL = in.URL },
				"region":   func() { cfg.Region = in.Region },
				"audience": func() { cfg.Audience = in.Audience },
				"profile":  func() { cfg.Profile = in.Profile },
				"local":    func() { cfg.Local = in.Local },
				"partner":  func() { root.Partner = partner },
			} {
				if f.Changed(name) {
					apply()
				}
			}
			if cfg.URL == "" {
				return errors.New("--url is required")
			}
			if !cfg.Local && (cfg.Region == "" || cfg.Audience == "") {
				return errors.New("--region and --audience are required (or --local)")
			}
			path, err := root.Save()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "saved %s\n", path)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&stage, "stage", "", "configure the server of this stage (dev, prod), when each stage has its own signer")
	f.StringVar(&in.URL, "url", "", "signing server URL (https://...)")
	f.StringVar(&in.Region, "region", "", "AWS region the server runs in")
	f.StringVar(&in.Audience, "audience", "", "server audience string (from the Terraform outputs)")
	f.StringVar(&in.Profile, "profile", "", "AWS profile to use (e.g. your SSO profile)")
	f.BoolVar(&in.Local, "local", false, "talk to a local \"adl-signer serve --local-insecure\"")
	f.StringVar(&partner, "partner", "", "partner to act for by default, if you may act for several (\"\" to clear)")
	register(cmd, map[string]completeFunc{
		"stage":    completeStage,
		"url":      fixed(root.URL, "http://127.0.0.1:8080"),
		"region":   completeRegion,
		"audience": fixed(root.Audience),
		"profile":  completeAWSProfile,
		"partner":  completePartner,
	})
	return cmd
}

func newWhoamiCommand() *cobra.Command {
	var stage string
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show the identity, permissions and environments the server sees for you",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient(cmd.Context(), stage)
			if err != nil {
				return err
			}
			w, err := c.WhoAmI(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "principal:   %s\narn:         %s\naccount:     %s\npermissions: %s\n", w.Principal, w.ARN, w.Account, strings.Join(w.Permissions, " "))
			if len(w.Environments) == 0 {
				fmt.Fprintln(out, "\nno environments")
				return nil
			}
			fmt.Fprintln(out)
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ENVIRONMENT\tPARTNER\tSTAGE\tYOU MAY")
			for _, e := range w.Environments {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Name, dash(e.Partner), e.Stage, strings.Join(e.Actions, " "))
			}
			return tw.Flush()
		},
	}
	serverFlag(cmd, &stage)
	return cmd
}

// newMintCommand is what most developers will ever run: one command, cert
// on disk, key backed up on the server.
func newMintCommand() *cobra.Command {
	var (
		stage, partner, id, mac, port, esptool, out, keyType string
		noEscrow, zipIt, replace                             bool
		lbl                                                  = labels{}
	)
	cmd := &cobra.Command{
		Use:   "mint",
		Short: "Mint a certificate for a dev board (cert, key and CA files on disk)",
		Long: `Mint a new device certificate. Where device IDs are made from the chip, give
the board's MAC with --mac, or --port to read it with esptool; otherwise the
server picks the next free number unless you give --id. The private key is
backed up (escrowed) on the server so "adl fetch" can bring it back.

Files written, in the layout flashing scripts expect:

  certs/<ID>/device/device-<ID>.crt         device certificate
  certs/<ID>/device/device-<ID>.key         private key (0600)
  certs/<ID>/device/device-<ID>-chain.pem   device cert + intermediate
  certs/<ID>/device/ca-chain.pem            intermediate + root
  certs/<ID>/device/ca-root.pem             root CA on its own
  certs/<ID>/bundle.json                    id / env / serial`,
		Example: `  adl mint --port /dev/ttyUSB0
  adl mint --mac 3c:71:bf:4a:12:e0 --label board=rev-c --label owner=jane
  adl mint --replace --id GLXADL017       # re-key, revokes the old cert
  adl mint --partner acme --stage dev --mac 00:11:22:33:44:55
  adl mint --zip --out ~/boards`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			c, err := newClient(ctx, stage)
			if err != nil {
				return err
			}
			envName, err := resolveEnv(ctx, c, partner, stage)
			if err != nil {
				return err
			}
			if port != "" {
				if mac != "" {
					return errors.New("pass --mac or --port, not both")
				}
				st := &eol.Station{Port: port, Esptool: esptool}
				if mac, err = st.ReadChipMAC(ctx); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "board MAC %s\n", mac)
			}
			key, err := pki.GenerateKey(keyType)
			if err != nil {
				return err
			}
			csr, err := pki.CreateCSR(key, pkix.Name{CommonName: id})
			if err != nil {
				return err
			}
			keyPEM, err := pki.EncodePrivateKey(key)
			if err != nil {
				return err
			}
			req := model.IssueRequest{Env: envName, DeviceID: id, CSR: string(csr), ChipID: mac, Labels: lbl, Replace: replace}
			if !noEscrow {
				req.PrivateKey = string(keyPEM)
			}
			resp, err := c.Issue(ctx, req)
			if err != nil {
				return err
			}
			b := &model.Bundle{DeviceID: resp.Device.ID, Env: resp.Device.Env, Serial: resp.Certificate.Serial,
				CertificatePEM: resp.CertificatePEM, ChainPEM: resp.ChainPEM, PrivateKeyPEM: string(keyPEM)}
			w := cmd.OutOrStdout()
			dir, err := writeBundle(cmd.ErrOrStderr(), out, b, zipIt)
			if err != nil {
				return fmt.Errorf("certificate %s was issued but writing files failed (recover with `adl fetch %s`): %w", b.DeviceID, b.DeviceID, err)
			}
			fmt.Fprintf(w, "minted %s (%s)\n  serial   %s\n  expires  %s\n  files    %s\n",
				b.DeviceID, b.Env, b.Serial, resp.Certificate.NotAfter.Format("2006-01-02"), dir)
			if resp.Certificate.KeyEscrowed {
				fmt.Fprintf(w, "  backup   private key escrowed; `adl fetch %s` gets everything back\n", b.DeviceID)
			} else {
				fmt.Fprintf(w, "  backup   key NOT escrowed - if you lose %s it is gone\n", filepath.Join(dir, "device-"+b.DeviceID+".key"))
			}
			return nil
		},
	}
	stageFlag(cmd, &stage, "dev", "stage (dev, prod)")
	partnerFlag(cmd, &partner, "partner to act for, if you may act for several")
	f := cmd.Flags()
	f.StringVar(&id, "id", "", "device id (default: made from the MAC, or the next free number)")
	f.StringVar(&mac, "mac", "", "the board's MAC (e.g. 3c:71:bf:4a:12:e0); device ids are made from it")
	f.StringVar(&port, "port", "", "read the MAC from the board on this serial port with esptool")
	f.StringVar(&esptool, "esptool", envOr("ADL_ESPTOOL", "esptool.py"), "esptool command, with --port (env ADL_ESPTOOL)")
	f.StringVar(&out, "out", "certs", "output directory")
	f.StringVar(&keyType, "key-type", "rsa2048", "rsa2048 or ecdsa-p256")
	f.BoolVar(&noEscrow, "no-escrow", false, "do not back up the private key on the server")
	f.BoolVar(&zipIt, "zip", false, "also write <ID>.zip")
	f.BoolVar(&replace, "replace", false, "re-issue an existing device id (revokes its current cert)")
	f.Var(lbl, "label", "key=value label, repeatable (e.g. --label board=rev-c --label owner=jane)")
	register(cmd, map[string]completeFunc{
		"id":       completeDeviceFlag,
		"mac":      completeNothing,
		"port":     completeSerialPort,
		"esptool":  fixed("esptool.py", "esptool"),
		"out":      completeDirs,
		"key-type": completeKeyType,
		"label":    completeLabel,
	})
	return cmd
}

func newFetchCommand() *cobra.Command {
	var (
		stage, out, serial string
		noKey, zipIt       bool
	)
	cmd := &cobra.Command{
		Use:   "fetch DEVICE_ID",
		Short: "Pull a device's cert, private key and CA certs back down",
		Long: `Pull everything for a device back to disk: the device certificate, its
escrowed private key, the CA chain and the root CA on its own. Use it when
you lost the files from "adl mint", or to get the files onto another machine.

Production keys are never escrowed, so for prod devices you get the public
parts only. Every fetch that includes a key is written to the audit log.`,
		Example: `  adl fetch GLXADL017
  adl fetch GLXADL017 --out ~/boards --zip
  adl fetch GLXADL017 --no-key            # certs only`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDeviceArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c, err := newClient(ctx, stage)
			if err != nil {
				return err
			}
			b, err := c.Bundle(ctx, args[0], serial, !noKey)
			if ae, ok := client.IsCode(err, "not_found"); ok && !noKey && strings.Contains(ae.Message, "escrowed") {
				fmt.Fprintln(cmd.ErrOrStderr(), "note: no escrowed key for this certificate, fetching certificate only")
				b, err = c.Bundle(ctx, args[0], serial, false)
			}
			if err != nil {
				return err
			}
			dir, err := writeBundle(cmd.ErrOrStderr(), out, b, zipIt)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (serial %s) to %s\n", b.DeviceID, b.Serial, dir)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&out, "out", "certs", "output directory")
	f.StringVar(&serial, "serial", "", "a specific certificate (default: current)")
	f.BoolVar(&noKey, "no-key", false, "skip the escrowed private key")
	f.BoolVar(&zipIt, "zip", false, "also write <ID>.zip")
	serverFlag(cmd, &stage)
	register(cmd, map[string]completeFunc{
		"out":    completeDirs,
		"serial": completeSerial,
	})
	return cmd
}

// writeBundle lays files out in the layout flashing scripts expect, so they
// work unchanged:
//
//	<out>/<ID>/device/device-<ID>.crt        leaf
//	<out>/<ID>/device/device-<ID>-chain.pem  leaf + intermediate
//	<out>/<ID>/device/device-<ID>.key        private key (0600)
//	<out>/<ID>/device/ca-chain.pem           intermediate + root
//	<out>/<ID>/device/ca-root.pem            root on its own
func writeBundle(log io.Writer, out string, b *model.Bundle, zipIt bool) (string, error) {
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
		if root := chain[len(chain)-1]; isSelfSigned(root) {
			files["ca-root.pem"] = pki.EncodeCertificates(root)
		}
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
			fmt.Fprintf(log, "moved existing %s to %s\n", p, backup)
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

func newListCommand() *cobra.Command {
	var (
		stage, partner string
		asJSON         bool
	)
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the devices you can see",
		Example: `  adl list
  adl list --stage prod
  adl list --partner acme --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			c, err := newClient(ctx, stage)
			if err != nil {
				return err
			}
			// Without --stage the server lists every environment you can read.
			envs := []string{""}
			switch {
			case stage != "":
				name, err := resolveEnv(ctx, c, partner, stage)
				if err != nil {
					return err
				}
				envs = []string{name}
			case partner != "":
				w, err := c.WhoAmI(ctx)
				if err != nil {
					return err
				}
				if envs = client.PartnerEnvs(w.Environments, partner); len(envs) == 0 {
					return fmt.Errorf("you cannot act for %s", partner)
				}
			}
			l := &model.DeviceList{}
			for _, e := range envs {
				part, err := c.ListDevices(ctx, e)
				if err != nil {
					return err
				}
				l.Devices = append(l.Devices, part.Devices...)
			}
			if asJSON {
				return printJSON(cmd.OutOrStdout(), l)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "DEVICE\tENV\tSTATUS\tOWNER\tCHIP\tCREATED")
			for _, d := range l.Devices {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", d.ID, d.Env, d.Status, d.Owner, dash(d.ChipID), d.CreatedAt.Format("2006-01-02"))
			}
			return tw.Flush()
		},
	}
	stageFlag(cmd, &stage, "", "only this stage")
	partnerFlag(cmd, &partner, "only this partner's devices")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func newShowCommand() *cobra.Command {
	var (
		stage  string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:               "show DEVICE_ID",
		Short:             "Show a device: status, labels and every cert it has had",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDeviceArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c, err := newClient(ctx, stage)
			if err != nil {
				return err
			}
			d, err := c.GetDevice(ctx, args[0])
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if asJSON {
				return printJSON(w, d)
			}
			dev := d.Device
			fmt.Fprintf(w, "device   %s (%s)\nstatus   %s\nowner    %s\nchip     %s\ncreated  %s\n",
				dev.ID, dev.Env, dev.Status, dev.Owner, dash(dev.ChipID), dev.CreatedAt.Format(time.RFC3339))
			if dev.ProvisionedAt != nil {
				fmt.Fprintf(w, "flashed  %s by %s on %s (fw %s)\n", dev.ProvisionedAt.Format(time.RFC3339), dev.ProvisionedBy, dev.Station, dash(dev.FirmwareVersion))
			}
			for k, v := range dev.Labels {
				fmt.Fprintf(w, "label    %s=%s\n", k, v)
			}
			fmt.Fprintln(w, "\ncertificates:")
			tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
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
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	serverFlag(cmd, &stage)
	return cmd
}

func newRevokeCommand() *cobra.Command {
	var (
		stage, reason, serial string
		yes                   bool
	)
	cmd := &cobra.Command{
		Use:   "revoke DEVICE_ID --reason REASON",
		Short: "Revoke a device's certificates",
		Example: `  adl revoke GLXADL017 --reason keyCompromise
  adl revoke GLXADL017 --reason superseded --serial 4f2a...`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDeviceArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes && !confirm(fmt.Sprintf("Revoke %s (%s)? This cannot be undone.", args[0], reason)) {
				return errors.New("aborted")
			}
			ctx := cmd.Context()
			c, err := newClient(ctx, stage)
			if err != nil {
				return err
			}
			d, err := c.Revoke(ctx, args[0], model.RevokeRequest{Serial: serial, Reason: reason})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is now %s\n", d.Device.ID, d.Device.Status)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&reason, "reason", "", "keyCompromise, superseded, cessationOfOperation, affiliationChanged or unspecified")
	f.StringVar(&serial, "serial", "", "only this certificate (default: all active certs of the device)")
	f.BoolVar(&yes, "yes", false, "do not ask for confirmation")
	_ = cmd.MarkFlagRequired("reason")
	serverFlag(cmd, &stage)
	register(cmd, map[string]completeFunc{
		"reason": completeReason,
		"serial": completeSerial,
	})
	return cmd
}

func newAuditCommand() *cobra.Command {
	var (
		stage, day string
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit log for a day",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			c, err := newClient(ctx, stage)
			if err != nil {
				return err
			}
			l, err := c.Audit(ctx, day)
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(cmd.OutOrStdout(), l)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "TIME\tACTOR\tACTION\tENV\tDEVICE\tSERIAL")
			for _, e := range l.Events {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.Time.Format(time.TimeOnly), e.Actor, e.Action, dash(e.Env), dash(e.DeviceID), dash(e.Serial))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&day, "day", "", "UTC day YYYY-MM-DD (default today)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	serverFlag(cmd, &stage)
	register(cmd, map[string]completeFunc{"day": completeDay})
	return cmd
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// isSelfSigned reports whether c is a root: it names itself as issuer and
// its own key verifies its signature.
func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
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
