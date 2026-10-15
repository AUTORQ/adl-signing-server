// Command adl is the client for the ADL signing server.
//
//	developers:   adl mint, adl fetch DVTADL017 (get it back after losing it)
//	factory:      adl eol check, adl eol provision --port /dev/ttyUSB0
//	CA admins:    adl ca ..., adl import, adl revoke, adl audit
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/edge-labs/adl-signing-server/internal/client"
	"github.com/edge-labs/adl-signing-server/internal/version"
)

const usage = `adl - device certificate tool

Words used here:
  partner      a manufacturing partner, by id (edge-labs). Its name on
               certificates (O=) is set by AutorQ.
  stage        dev or prod. Each stage has its own signer and intermediate.
  environment  a partner's stage on a signer (edge-labs-dev). You never need
               to type it: your identity decides the partner, --stage the
               stage. People who may act for several partners (AutorQ staff)
               add --partner, or set a default with "adl configure --partner".
  device id    the partner's prefix + the board's MAC (DVTADL3C71BF4A12E0),
               the same in every stage. Not the certificate serial (--serial).

Setup:
  adl configure [--stage dev|prod] --url URL --region REGION --audience AUD [--profile AWS_PROFILE] [--partner P]
  adl whoami [--stage S]

Developers:
  adl mint  [--stage dev] (--mac MAC | --port PORT | --id ID) [--label k=v] [--out DIR] [--zip] [--no-escrow] [--replace]
  adl fetch ID [--stage S] [--out DIR] [--serial S] [--no-key]
  adl list  [--stage S] [--partner P]
  adl show  ID [--stage S]

End of line (factory):
  adl eol check     [--stage prod] --station NAME [--port PORT]
  adl eol provision [--stage prod] --station NAME --port PORT [--firmware VER] [--reissue] [--loop]

Admin:
  adl revoke ID --reason REASON [--stage S] [--serial S]
  adl ca status  --stage S
  adl ca csr     --stage S --cn NAME [--org O] [--ou OU] [--country C] [--out FILE]
  adl ca install --stage S --chain FILE
  adl ca crl     --stage S [--out FILE]
  adl import --stage S --dir DIR [--with-keys] [--provisioned] [--dry-run]
  adl audit [--stage S] [--day YYYY-MM-DD]

Commands with --stage also take --partner. With a signer per stage,
configure each with "adl configure --stage dev|prod ..."; --stage then also
picks the server. --env is the older spelling of --stage and still works.
Run "adl <command> -h" for the flags of a command.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) {
			fmt.Fprintf(os.Stderr, "error: %s\n", ae.Message)
			if ae.Code != "" {
				fmt.Fprintf(os.Stderr, "       code=%s", ae.Code)
				if ae.RequestID != "" {
					fmt.Fprintf(os.Stderr, " request=%s", ae.RequestID)
				}
				fmt.Fprintln(os.Stderr)
			}
		} else {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(usage)
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Println(version.String())
		return nil
	case "configure":
		return cmdConfigure(rest)
	case "whoami":
		return cmdWhoami(ctx, rest)
	case "mint":
		return cmdMint(ctx, rest)
	case "fetch":
		return cmdFetch(ctx, rest)
	case "list", "ls":
		return cmdList(ctx, rest)
	case "show":
		return cmdShow(ctx, rest)
	case "revoke":
		return cmdRevoke(ctx, rest)
	case "eol":
		return cmdEOL(ctx, rest)
	case "ca":
		return cmdCA(ctx, rest)
	case "import":
		return cmdImport(ctx, rest)
	case "audit":
		return cmdAudit(ctx, rest)
	}
	return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
}

// defaultPartner is the partner set with `adl configure --partner` (or
// ADL_PARTNER), used when --partner is not given.
func defaultPartner() string {
	if cfg, err := client.LoadConfig(); err == nil {
		return cfg.Partner
	}
	return ""
}

// stageFlag registers --stage, and --env, its spelling from before there
// were partners. Both take a stage (dev, prod) or a full environment name
// (edge-labs-prod); with a partner, the CLI works out the environment.
func stageFlag(fs *flag.FlagSet, def, usage string) *string {
	v := new(string)
	fs.StringVar(v, "stage", def, usage)
	fs.StringVar(v, "env", def, "same as --stage")
	return v
}

// serverFlag adds --stage to commands that only need it to pick a server.
func serverFlag(fs *flag.FlagSet) *string {
	return stageFlag(fs, "", "stage whose server to ask (dev, prod), when each stage has its own")
}

// resolveEnv maps --stage (a stage or a full name) and --partner to the
// environment the server knows, using what the caller may access.
func resolveEnv(ctx context.Context, c *client.Client, partner, want string) (string, error) {
	w, err := c.WhoAmI(ctx)
	if err != nil {
		return "", err
	}
	return client.ResolveEnv(w.Environments, partner, want)
}

// newClient connects to the server for env (a stage or environment name;
// empty for the default server).
func newClient(ctx context.Context, env string) (*client.Client, error) {
	cfg, err := client.LoadConfig()
	if err != nil {
		return nil, err
	}
	srv, err := cfg.ForStage(env)
	if err != nil {
		return nil, err
	}
	return client.New(ctx, srv)
}

// labels collects repeated --label k=v flags.
type labels map[string]string

func (l labels) String() string { return "" }

func (l labels) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return fmt.Errorf("label must be key=value")
	}
	l[k] = val
	return nil
}

// splitArgs separates flags from positional args so "adl fetch ID --out x"
// works as well as "adl fetch --out x ID".
func splitArgs(args []string, boolFlags ...string) (flags, positional []string) {
	isBool := map[string]bool{}
	for _, b := range boolFlags {
		isBool[b] = true
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(name, "=") && !isBool[name] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	return flags, positional
}
