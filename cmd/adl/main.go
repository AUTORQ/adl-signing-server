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

--env takes a stage (dev, prod) or a full environment name (edge-labs-dev).
Your identity decides which partner's environments you reach; people who may
act for several partners (AutorQ staff) pick one with --partner or set a
default with "adl configure --partner".

Setup:
  adl configure [--stage dev|prod] --url URL --region REGION --audience AUD [--profile AWS_PROFILE] [--partner P]
  adl whoami [--env dev|prod]

Developers:
  adl mint  [--env dev] (--mac MAC | --port PORT | --id ID) [--move] [--label k=v] [--out DIR] [--zip] [--no-escrow] [--replace]
  adl fetch ID [--out DIR] [--serial S] [--no-key]
  adl list  [--env dev|prod] [--partner P]
  adl show  ID

End of line (factory):
  adl eol check     [--env prod] --station NAME [--port PORT]
  adl eol provision [--env prod] --station NAME --port PORT [--firmware VER] [--reissue] [--move] [--loop]

Admin:
  adl revoke ID --reason REASON [--serial S]
  adl ca status  --env ENV
  adl ca csr     --env ENV --cn NAME [--org O] [--ou OU] [--country C] [--out FILE]
  adl ca install --env ENV --chain FILE
  adl ca crl     --env ENV [--out FILE]
  adl import --env ENV --dir DIR [--with-keys] [--provisioned] [--dry-run]
  adl audit [--day YYYY-MM-DD]

Commands that take --env also take --partner. With one signer per stage,
configure each with "adl configure --stage dev|prod ..."; --env then also
picks the server (fetch, show, revoke and audit take --env for that too).
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

// serverFlag adds --env to commands that only need it to pick a server.
func serverFlag(fs *flag.FlagSet) *string {
	return fs.String("env", "", "stage whose server to ask (dev, prod), when each stage has its own")
}

// resolveEnv maps --env (a stage or a full name) and --partner to the
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
	if cfg, err = cfg.ForEnv(env); err != nil {
		return nil, err
	}
	return client.New(ctx, cfg)
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
