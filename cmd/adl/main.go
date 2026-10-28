// Command adl is the client for the ADL signing server.
//
//	developers:   adl mint, adl fetch GLXADL017 (get it back after losing it)
//	factory:      adl eol check, adl eol provision --port /dev/ttyUSB0
//	CA admins:    adl ca ..., adl import, adl revoke, adl audit
//	everyone:     adl install (binary + shell completion)
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/AUTORQ/adl-signing-server/internal/client"
	"github.com/AUTORQ/adl-signing-server/internal/cliinstall"
	"github.com/AUTORQ/adl-signing-server/internal/version"
)

const (
	groupSetup   = "setup"
	groupDev     = "dev"
	groupFactory = "factory"
	groupAdmin   = "admin"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRootCommand().ExecuteContext(ctx); err != nil {
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

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "adl",
		Short: "Device certificate tool",
		Long: `adl - device certificate tool

First time on a machine:
  adl install                 put adl on PATH with tab completion
  adl configure --url ...     point it at the signing server
  adl whoami                  check who the server thinks you are

Dev board:     adl mint --port /dev/ttyUSB0 (mint and flash), see adl flash --help
Factory line:  adl eol --help walks through the flashing station step by step

Words used here:
  partner      a manufacturing partner, by id (globex). Its name on
               certificates (O=) is set by whoever runs the signer.
  stage        dev or prod. Each stage has its own signer and intermediate.
  environment  a partner's stage on a signer (globex-dev). You never need
               to type it: your identity decides the partner, --stage the
               stage. People who may act for several partners (the signer's
               operators) add --partner, or set a default with
               "adl configure --partner".
  device id    the prefix + the board's MAC (GLXADL3C71BF4A12E0), the same in
               every stage, or + a number (GLXADL017), depending on how the
               environment is set up. Not the certificate serial (--serial).

With a signer per stage, configure each with "adl configure --stage dev|prod";
--stage then also picks the server. --env is the older spelling of --stage.`,
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddGroup(
		&cobra.Group{ID: groupSetup, Title: "Setup:"},
		&cobra.Group{ID: groupDev, Title: "Developers:"},
		&cobra.Group{ID: groupFactory, Title: "End of line (factory flashing):"},
		&cobra.Group{ID: groupAdmin, Title: "CA admins:"},
	)

	add := func(group string, cmds ...*cobra.Command) {
		for _, c := range cmds {
			c.GroupID = group
			root.AddCommand(c)
		}
	}
	add(groupSetup, newConfigureCommand(), newWhoamiCommand(), newVersionCommand())
	add(groupDev, newMintCommand(), newFlashCommand(), newFetchCommand(), newListCommand(), newShowCommand())
	add(groupFactory, newEOLCommand())
	add(groupAdmin, newRevokeCommand(), newCACommand(), newImportCommand(), newAuditCommand())

	install := cliinstall.Attach(root)
	install.GroupID = groupSetup
	root.SetCompletionCommandGroupID(groupSetup)
	return root
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.String())
		},
	}
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
// (globex-prod); with a partner, the CLI works out the environment.
func stageFlag(cmd *cobra.Command, v *string, def, usage string) {
	f := cmd.Flags()
	f.StringVar(v, "stage", def, usage)
	f.StringVar(v, "env", def, "same as --stage")
	_ = f.MarkHidden("env")
	register(cmd, map[string]completeFunc{"stage": completeStage, "env": completeStage})
}

// serverFlag adds --stage to commands that only need it to pick a server.
func serverFlag(cmd *cobra.Command, v *string) {
	stageFlag(cmd, v, "", "stage whose server to ask (dev, prod), when each stage has its own")
}

// partnerFlag adds --partner, defaulting to the configured partner.
func partnerFlag(cmd *cobra.Command, v *string, usage string) {
	cmd.Flags().StringVar(v, "partner", defaultPartner(), usage)
	register(cmd, map[string]completeFunc{"partner": completePartner})
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

func (l labels) Type() string { return "key=value" }

func (l labels) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return fmt.Errorf("label must be key=value")
	}
	l[k] = val
	return nil
}
