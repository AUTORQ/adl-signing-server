package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/AUTORQ/adl-signing-server/internal/client"
	"github.com/AUTORQ/adl-signing-server/internal/eol"
	"github.com/AUTORQ/adl-signing-server/internal/model"
	"github.com/AUTORQ/adl-signing-server/internal/pki"
)

func newCACommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Intermediate CA: status, pull certs, CSR, install, CRL",
		Long: `Manage the intermediate CA of an environment. The CA private key lives in KMS
and never leaves it; these commands only move certificates around.

"status", "pull" and "crl" need no permission, only a sign-in so adl can work
out your environment. "csr" and "install" need ca:admin and are part of the
ceremony in docs/ca-ceremony.md.`,
	}
	cmd.AddCommand(newCAStatusCommand(), newCAPullCommand(), newCACSRCommand(), newCAInstallCommand(), newCACRLCommand())
	return cmd
}

// caEnv holds the --stage and --partner every ca subcommand takes.
type caEnv struct{ stage, partner string }

func (e *caEnv) bind(cmd *cobra.Command) {
	stageFlag(cmd, &e.stage, "", "stage (dev, prod), required")
	partnerFlag(cmd, &e.partner, "partner whose intermediate this is")
}

// client connects to the stage's server and resolves the environment.
func (e *caEnv) client(cmd *cobra.Command) (*client.Client, string, error) {
	if e.stage == "" {
		return nil, "", errors.New("--stage is required")
	}
	ctx := cmd.Context()
	c, err := newClient(ctx, e.stage)
	if err != nil {
		return nil, "", err
	}
	env, err := resolveEnv(ctx, c, e.partner, e.stage)
	if err != nil {
		return nil, "", err
	}
	return c, env, nil
}

func newCAStatusCommand() *cobra.Command {
	var (
		e   caEnv
		out string
	)
	cmd := &cobra.Command{
		Use:     "status --stage STAGE",
		Short:   "Show the installed intermediate and when it expires",
		Example: "  adl ca status --stage prod",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, env, err := e.client(cmd)
			if err != nil {
				return err
			}
			st, err := c.CAStatus(cmd.Context(), env)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "env          %s\nconfigured   %v\nkms key      %s sha256:%s\n", st.Env, st.Configured, st.KeyAlgorithm, st.PublicKeySHA256)
			if st.Configured {
				fmt.Fprintf(w, "subject      %s\nissuer       %s\nvalid        %s .. %s\nfingerprint  %s\n",
					st.Subject, st.Issuer, st.NotBefore.Format("2006-01-02"), st.NotAfter.Format("2006-01-02"), st.FingerprintSHA256)
				if d := time.Until(st.NotAfter); d < 365*24*time.Hour {
					fmt.Fprintf(w, "WARNING      intermediate expires in %d days, plan the rotation\n", int(d.Hours()/24))
				}
			}
			if out != "" && st.ChainPEM != "" {
				return os.WriteFile(out, []byte(st.ChainPEM), 0o644)
			}
			return nil
		},
	}
	e.bind(cmd)
	cmd.Flags().StringVar(&out, "out", "", "also write the CA chain (intermediate + root) to this file")
	register(cmd, map[string]completeFunc{"out": completeFiles})
	return cmd
}

func newCAPullCommand() *cobra.Command {
	var (
		e   caEnv
		out string
	)
	cmd := &cobra.Command{
		Use:   "pull --stage STAGE",
		Short: "Download the root CA, intermediate and chain certificates",
		Long: `Download the public CA certificates of an environment, for firmware builds,
cloud trust stores or a flashing station:

  <out>/<env>-root.pem           root CA on its own
  <out>/<env>-intermediate.pem   the intermediate that signs devices
  <out>/<env>-ca-chain.pem       intermediate + root

<env> is the environment's full name (globex-prod). These are certificates
only. The intermediate's private key is held in KMS and cannot be exported.
For one device's cert and private key use "adl fetch DEVICE_ID".`,
		Example: `  adl ca pull --stage prod
  adl ca pull --stage dev --out firmware/certs`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, env, err := e.client(cmd)
			if err != nil {
				return err
			}
			st, err := c.CAStatus(cmd.Context(), env)
			if err != nil {
				return err
			}
			if !st.Configured || st.ChainPEM == "" {
				return fmt.Errorf("no CA installed for %s yet (see docs/ca-ceremony.md)", env)
			}
			chain, err := pki.ParseCertificates([]byte(st.ChainPEM))
			if err != nil {
				return err
			}
			files := map[string][]byte{
				env + "-intermediate.pem": pki.EncodeCertificates(chain[0]),
				env + "-ca-chain.pem":     []byte(st.ChainPEM),
			}
			if root := chain[len(chain)-1]; len(chain) > 1 && isSelfSigned(root) {
				files[env+"-root.pem"] = pki.EncodeCertificates(root)
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: the %s chain does not end in a self signed root; no root file written\n", env)
			}
			if err := os.MkdirAll(out, 0o755); err != nil {
				return err
			}
			names := make([]string, 0, len(files))
			for name := range files {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				p := filepath.Join(out, name)
				if err := os.WriteFile(p, files[name], 0o644); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", p)
			}
			return nil
		},
	}
	e.bind(cmd)
	cmd.Flags().StringVar(&out, "out", ".", "directory to write the certificates into")
	register(cmd, map[string]completeFunc{"out": completeDirs})
	return cmd
}

func newCACSRCommand() *cobra.Command {
	var (
		e                         caEnv
		out, cn, org, ou, country string
	)
	cmd := &cobra.Command{
		Use:     "csr --stage STAGE --cn NAME",
		Short:   "Have KMS sign a CSR for a new intermediate (ca:admin)",
		Example: `  adl ca csr --partner globex --stage prod --cn "Globex Intermediate CA prod" --out prod-intermediate.csr`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, env, err := e.client(cmd)
			if err != nil {
				return err
			}
			r, err := c.CACSR(cmd.Context(), env, model.CACSRRequest{CommonName: cn, Organization: org, OrganizationalUnit: ou, Country: country})
			if err != nil {
				return err
			}
			return writeOrPrint(cmd, out, []byte(r.CSRPEM))
		},
	}
	e.bind(cmd)
	f := cmd.Flags()
	f.StringVar(&cn, "cn", "", "common name, e.g. \"Globex Intermediate CA prod\"")
	f.StringVar(&org, "org", "", "O= of the CSR (default: the environment's organization, i.e. the partner's name)")
	f.StringVar(&ou, "ou", "IoT Devices", "organizational unit")
	f.StringVar(&country, "country", "US", "country")
	f.StringVar(&out, "out", "", "write the CSR to this file instead of stdout")
	_ = cmd.MarkFlagRequired("cn")
	register(cmd, map[string]completeFunc{
		"cn":      completeNothing,
		"org":     completeNothing,
		"ou":      fixed("IoT Devices"),
		"country": fixed("US"),
		"out":     completeFiles,
	})
	return cmd
}

func newCAInstallCommand() *cobra.Command {
	var (
		e         caEnv
		chainFile string
	)
	cmd := &cobra.Command{
		Use:     "install --stage STAGE --chain FILE",
		Short:   "Install the signed intermediate chain (ca:admin)",
		Example: "  adl ca install --stage prod --chain prod-chain.pem",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			data, err := os.ReadFile(chainFile)
			if err != nil {
				return err
			}
			c, env, err := e.client(cmd)
			if err != nil {
				return err
			}
			st, err := c.CAInstall(cmd.Context(), env, model.CAInstallRequest{ChainPEM: string(data)})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "installed %s CA\n  subject     %s\n  issuer      %s\n  expires     %s\n  fingerprint %s\n",
				st.Env, st.Subject, st.Issuer, st.NotAfter.Format("2006-01-02"), st.FingerprintSHA256)
			return nil
		},
	}
	e.bind(cmd)
	cmd.Flags().StringVar(&chainFile, "chain", "", "PEM file: signed intermediate first, then up to and including the root")
	_ = cmd.MarkFlagRequired("chain")
	register(cmd, map[string]completeFunc{"chain": completePEM})
	return cmd
}

func newCACRLCommand() *cobra.Command {
	var (
		e   caEnv
		out string
	)
	cmd := &cobra.Command{
		Use:     "crl --stage STAGE --out FILE",
		Short:   "Download the current CRL (DER)",
		Example: "  adl ca crl --stage prod --out prod.crl",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, env, err := e.client(cmd)
			if err != nil {
				return err
			}
			der, err := c.CRL(cmd.Context(), env)
			if err != nil {
				return err
			}
			return os.WriteFile(out, der, 0o644)
		},
	}
	e.bind(cmd)
	cmd.Flags().StringVar(&out, "out", "", "file to write (the CRL is binary DER)")
	_ = cmd.MarkFlagRequired("out")
	register(cmd, map[string]completeFunc{"out": completeFiles})
	return cmd
}

func writeOrPrint(cmd *cobra.Command, path string, data []byte) error {
	if path == "" {
		_, err := cmd.OutOrStdout().Write(data)
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", path)
	return nil
}

var legacyCertRE = regexp.MustCompile(`^device-([A-Za-z0-9_-]+)\.crt$`)

func newImportCommand() *cobra.Command {
	var (
		stage, partner, dir           string
		withKeys, provisioned, dryRun bool
	)
	cmd := &cobra.Command{
		Use:   "import --stage STAGE --dir DIR",
		Short: "Register certificates issued before the signer (admin:import)",
		Long: `Walk a directory of existing device certificates and register every
device-<ID>.crt in it, so devices already in the field keep working and show
up in "adl list". Run with --dry-run first. See docs/ca-ceremony.md.`,
		Example: `  adl import --stage dev  --dir old-ca/dev/device  --with-keys --dry-run
  adl import --stage prod --dir old-ca/prod/device --provisioned`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runImport(cmd, stage, partner, dir, withKeys, provisioned, dryRun)
		},
	}
	stageFlag(cmd, &stage, "", "stage the certs belong to, required")
	partnerFlag(cmd, &partner, "partner the certs belong to")
	f := cmd.Flags()
	f.StringVar(&dir, "dir", "", "directory to scan for device-<ID>.crt files")
	f.BoolVar(&withKeys, "with-keys", false, "also escrow device-<ID>.key files (only allowed where escrow is on)")
	f.BoolVar(&provisioned, "provisioned", false, "mark imported devices as provisioned (they are already in the field)")
	f.BoolVar(&dryRun, "dry-run", false, "show what would be imported")
	_ = cmd.MarkFlagRequired("dir")
	register(cmd, map[string]completeFunc{"dir": completeDirs})
	return cmd
}

// runImport walks a directory of existing device certificates and registers
// every device certificate in it.
func runImport(cmd *cobra.Command, env, partner, dir string, withKeys, provisioned, dryRun bool) error {
	if env == "" {
		return errors.New("--stage is required")
	}
	ctx := cmd.Context()
	w := cmd.OutOrStdout()
	type found struct{ cert, key, chain string }
	byID := map[string]*found{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
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
		return fmt.Errorf("no device-<ID>.crt files under %s", dir)
	}

	var c *client.Client
	if !dryRun {
		if c, err = newClient(ctx, env); err != nil {
			return err
		}
		if env, err = resolveEnv(ctx, c, partner, env); err != nil {
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
		req := model.ImportRequest{Env: env, CertificatePEM: string(certPEM), Provisioned: provisioned}
		if f.chain != "" {
			// The legacy chain file is leaf + intermediate; we want the
			// issuer part only.
			data, _ := os.ReadFile(f.chain)
			if certs, err := pki.ParseCertificates(data); err == nil && len(certs) > 1 {
				req.ChainPEM = string(pki.EncodeCertificates(certs[1:]...))
			}
		}
		if withKeys && f.key != "" {
			data, _ := os.ReadFile(f.key)
			req.PrivateKeyPEM = string(data)
		}
		if dryRun {
			fmt.Fprintf(w, "would import %-12s key=%v chain=%v\n", id, req.PrivateKeyPEM != "", req.ChainPEM != "")
			continue
		}
		_, err = c.Import(ctx, req)
		switch {
		case err == nil:
			ok++
			fmt.Fprintf(w, "imported %s\n", id)
		case isCode(err, "already_imported"):
			skipped++
			fmt.Fprintf(w, "skipped  %s (already registered)\n", id)
		default:
			failed++
			fmt.Fprintf(w, "FAILED   %s: %v\n", id, err)
		}
	}
	if !dryRun {
		fmt.Fprintf(w, "\n%d imported, %d already there, %d failed\n", ok, skipped, failed)
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

const eolLong = `Flash production identities onto ESP32-S3 boards at the end of the line.

ONE-TIME STATION SETUP
  1. Install esptool and esp-secure-cert-tool at the versions you tested:
       pip install esptool==<ver> esp-secure-cert-tool==<ver>
  2. Put adl on PATH, and the flash script where adl looks for it:
       adl install
       mkdir -p ~/.local/share/adl && cp flash-esp32s3.sh ~/.local/share/adl/
     (machine-wide: sudo adl install system, script in /usr/local/share/adl;
     or point ADL_FLASH_SCRIPT at the script)
  3. Point adl at the prod signer with the station's AWS profile:
       adl configure --stage prod --url https://signer.example --region us-east-1 \
                     --audience adl-signing-server:123456789012 --profile factory
  4. Name the station (recorded against every board it flashes):
       export ADL_STATION=line-1
  5. Check everything. This must end with "station ready":
       adl eol check

EVERY SHIFT
  aws sso login --profile factory          (if the station uses SSO)
  adl eol check
  adl eol provision --port /dev/ttyUSB0 --firmware 1.4.2 --loop

  With --loop, plug in a board, wait for PASS or FAIL, press Enter, repeat.
  Ctrl-C stops between boards.

WHAT HAPPENS TO EACH BOARD
  1. esptool reads the chip MAC (the board's permanent ID in the registry)
  2. a new RSA-2048 key is made on this PC, in memory only
  3. the CSR and MAC go to the signer, which hands back the device ID
     (prefix + MAC, or the next number) and a certificate signed by the
     prod CA
  4. key and certs go to a private tmpfs dir, then the flash script runs
  5. the verify script runs (if set), then the tmpfs dir is wiped
  6. the server marks the board provisioned
  7. a PASS or FAIL banner prints and a line goes to the CSV log

WHEN A BOARD FAILS
  flash or verify failed, cable pulled   fix it and run again on the SAME
                                         board; it keeps its device ID
  "already provisioned as <ID>"          stop and set the board aside; it has
                                         been through the line already
  server unreachable / token expired     check network and AWS login, run
                                         again; nothing was written yet
  board must be re-keyed on purpose      a CA admin runs with --reissue

SETTINGS FROM THE ENVIRONMENT
  ADL_STATION            --station
  ADL_PORT               --port
  ADL_FIRMWARE_VERSION   --firmware
  ADL_FLASH_SCRIPT       --flash-script
  ADL_VERIFY_SCRIPT      --verify-script
  ADL_ESPTOOL            --esptool

Run "adl eol provision --help" for every flag and the flash script contract.
The long form is docs/eol-provisioning.md.`

const provisionLong = `Provision the board on --port: read its MAC, issue a prod certificate, flash
it and confirm it with the server. See "adl eol --help" for the full station
walkthrough and what to do when a board fails.

FLASH SCRIPT CONTRACT
The flash script (and verify script) get these environment variables and
must exit 0 only if the board is good:

  ADL_PORT, ADL_CHIP, ADL_ESPTOOL   where and how to talk to the board
  ADL_DEVICE_ID, ADL_SERIAL         identity being written
  ADL_CHIP_MAC, ADL_ENV
  ADL_KEY_ALGORITHM                 key type of the device key
  ADL_DEVICE_KEY                    path to the PEM private key (PKCS#8)
  ADL_DEVICE_CERT                   path to the device certificate
  ADL_DEVICE_CHAIN                  path to device cert + intermediate
  ADL_CA_CHAIN                      path to intermediate + root
  ADL_CA_ROOT                       path to the root only
  ADL_WORK_DIR                      the tmpfs dir, wiped afterwards

The default flash-esp32s3.sh burns an eFuse HMAC key for the DS peripheral.
eFuse burns are permanent: try the whole flow on scrap boards first.`

// eolOptions are the flags check and provision share.
type eolOptions struct {
	stage, partner, station, port, chip, esptool string
	flashScript, verifyScript                    string
	firmware, keyType, logPath                   string
}

func (o *eolOptions) bind(cmd *cobra.Command) {
	stageFlag(cmd, &o.stage, "prod", "stage to provision into")
	partnerFlag(cmd, &o.partner, "partner to act for, if you may act for several")
	f := cmd.Flags()
	f.StringVar(&o.station, "station", os.Getenv("ADL_STATION"), "station name, recorded against every device (env ADL_STATION)")
	f.StringVar(&o.port, "port", os.Getenv("ADL_PORT"), "serial port of the board, e.g. /dev/ttyUSB0 (env ADL_PORT)")
	f.StringVar(&o.chip, "chip", "esp32s3", "esptool chip type")
	f.StringVar(&o.esptool, "esptool", envOr("ADL_ESPTOOL", "esptool.py"), "esptool command (env ADL_ESPTOOL)")
	f.StringVar(&o.flashScript, "flash-script", envOr("ADL_FLASH_SCRIPT", defaultScript("flash-esp32s3.sh")), "script that writes the credentials to the board (env ADL_FLASH_SCRIPT)")
	f.StringVar(&o.verifyScript, "verify-script", os.Getenv("ADL_VERIFY_SCRIPT"), "optional script run after flashing (env ADL_VERIFY_SCRIPT)")
	f.StringVar(&o.firmware, "firmware", os.Getenv("ADL_FIRMWARE_VERSION"), "firmware version on the line, recorded with the device (env ADL_FIRMWARE_VERSION)")
	f.StringVar(&o.keyType, "key-type", "rsa2048", "rsa2048 (needed for the ESP32-S3 DS peripheral) or ecdsa-p256")
	f.StringVar(&o.logPath, "log", defaultLogPath(), "CSV log of every board this station touched")
	register(cmd, map[string]completeFunc{
		"station":       completeStation,
		"port":          completeSerialPort,
		"chip":          fixed("esp32s3"),
		"esptool":       fixed("esptool.py", "esptool"),
		"flash-script":  completeScripts,
		"verify-script": completeScripts,
		"firmware":      fixed(os.Getenv("ADL_FIRMWARE_VERSION")),
		"key-type":      completeKeyType,
		"log":           completeFiles,
	})
}

func (o *eolOptions) newStation(cmd *cobra.Command) (*eol.Station, error) {
	ctx := cmd.Context()
	c, err := newClient(ctx, o.stage)
	if err != nil {
		return nil, err
	}
	env, err := resolveEnv(ctx, c, o.partner, o.stage)
	if err != nil {
		return nil, err
	}
	return &eol.Station{
		Client: c, Env: env, Name: o.station, Port: o.port, Chip: o.chip, Esptool: o.esptool,
		FlashScript: o.flashScript, VerifyScript: o.verifyScript, Firmware: o.firmware,
		KeyType: o.keyType, LogPath: o.logPath, Out: cmd.OutOrStdout(),
	}, nil
}

func newEOLCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "eol",
		Short: "Flash production identities onto ESP32-S3 boards (start with: adl eol --help)",
		Long:  eolLong,
		Example: `  adl eol check
  adl eol provision --port /dev/ttyUSB0 --firmware 1.4.2 --loop`,
	}
	cmd.AddCommand(newEOLCheckCommand(), newEOLProvisionCommand())
	return cmd
}

func newEOLCheckCommand() *cobra.Command {
	var o eolOptions
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check the station is ready: identity, permissions, prod CA, esptool, scripts",
		Long: `Check the station before a shift: who the server thinks you are, that you
may issue, provision and read in the prod environment, that the prod CA is
installed, and that esptool and the flash script are present. Prints
"station ready" when everything is in place.`,
		Example: "  ADL_STATION=line-1 adl eol check",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := o.newStation(cmd)
			if err != nil {
				return err
			}
			if err := st.Preflight(cmd.Context()); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "station ready")
			return nil
		},
	}
	o.bind(cmd)
	return cmd
}

func newEOLProvisionCommand() *cobra.Command {
	var (
		o             eolOptions
		id            string
		reissue, loop bool
	)
	cmd := &cobra.Command{
		Use:   "provision --port PORT",
		Short: "Issue and flash the board on --port (with --loop, one board after another)",
		Long:  provisionLong,
		Example: `  adl eol provision --port /dev/ttyUSB0 --firmware 1.4.2 --loop
  adl eol provision --port /dev/ttyUSB0 --verify-script ./verify.sh
  adl eol provision --port /dev/ttyUSB0 --reissue      # CA admin only`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.port == "" {
				return errors.New("--port is required (or set ADL_PORT)")
			}
			st, err := o.newStation(cmd)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			if err := st.Preflight(ctx); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			in := bufio.NewReader(cmd.InOrStdin())
			for {
				res, err := st.Provision(ctx, eol.Options{DeviceID: id, Reissue: reissue})
				if err != nil {
					banner(w, "FAIL", err.Error())
				} else {
					msg := fmt.Sprintf("%s  serial %s  chip %s", res.DeviceID, res.Serial, res.ChipID)
					if res.Reissued {
						msg += "  (re-issued)"
					}
					banner(w, "PASS", msg)
				}
				if !loop {
					return err
				}
				fmt.Fprint(w, "\nconnect the next board and press Enter (Ctrl-C to stop) ")
				if _, rerr := in.ReadString('\n'); rerr != nil {
					return nil
				}
				id = ""
			}
		},
	}
	o.bind(cmd)
	f := cmd.Flags()
	f.BoolVar(&reissue, "reissue", false, "re-key a board that is already provisioned (needs revoke permission)")
	f.StringVar(&id, "id", "", "force a device id instead of allocating one")
	f.BoolVar(&loop, "loop", false, "keep going: provision, then wait for the next board")
	register(cmd, map[string]completeFunc{"id": completeDeviceFlag})
	return cmd
}

func banner(w io.Writer, status, msg string) {
	line := strings.Repeat("=", 60)
	fmt.Fprintf(w, "\n%s\n  %s  %s\n%s\n", line, status, msg, line)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// defaultScript looks for the bundled script next to the binary, then in
// ../share/adl (where it goes beside an `adl install`ed binary), then in the
// repo layout.
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
