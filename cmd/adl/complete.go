package main

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/AUTORQ/adl-signing-server/internal/pki"
)

// completionTimeout bounds every lookup a tab press makes against the
// server, so an unreachable signer or an expired SSO session never hangs
// the shell.
const completionTimeout = 2 * time.Second

type completeFunc = func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)

// fixed completes a flag or argument from a fixed list.
func fixed(values ...string) completeFunc {
	return func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

var (
	completeStage   = fixed("dev", "prod")
	completeKeyType = fixed("rsa2048", "ecdsa-p256")
	completeReason  = fixed(pki.ReasonNames()...)
	completeNothing = fixed()
)

func completeDirs(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveFilterDirs
}

func completeFiles(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveDefault
}

func completePEM(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return []string{"pem", "crt"}, cobra.ShellCompDirectiveFilterFileExt
}

func completeScripts(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return []string{"sh"}, cobra.ShellCompDirectiveFilterFileExt
}

// stageOf is the --stage the user has typed so far, which picks the server
// a completion asks.
func stageOf(cmd *cobra.Command) string {
	stage, _ := cmd.Flags().GetString("stage")
	return stage
}

// completeDeviceArg completes the first positional argument with device IDs.
func completeDeviceArg(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return knownDeviceIDs(cmd, false), cobra.ShellCompDirectiveNoFileComp
}

// completeDeviceFlag completes --id with the devices of --stage only, so a
// prod station is not offered dev boards.
func completeDeviceFlag(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return knownDeviceIDs(cmd, true), cobra.ShellCompDirectiveNoFileComp
}

// completePartner lists the partners the caller may act for.
func completePartner(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	ctx, cancel := context.WithTimeout(context.Background(), completionTimeout)
	defer cancel()
	c, err := newClient(ctx, stageOf(cmd))
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	w, err := c.WhoAmI(ctx)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range w.Environments {
		if e.Partner != "" && !seen[e.Partner] {
			seen[e.Partner] = true
			out = append(out, e.Partner)
		}
	}
	sort.Strings(out)
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeSerial lists the certificate serials of the device named in the
// first argument.
func completeSerial(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ctx, cancel := context.WithTimeout(context.Background(), completionTimeout)
	defer cancel()
	c, err := newClient(ctx, stageOf(cmd))
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	d, err := c.GetDevice(ctx, args[0])
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	out := make([]string, 0, len(d.Certificates))
	for _, cert := range d.Certificates {
		out = append(out, cert.Serial+"\t"+string(cert.Status)+" "+cert.IssuedAt.Format("2006-01-02"))
	}
	return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveKeepOrder
}

// knownDeviceIDs asks the server for the devices the caller can see, only
// those of --stage when onlyStage is set. It runs on a short leash and
// swallows every failure: completion must never print errors or block.
func knownDeviceIDs(cmd *cobra.Command, onlyStage bool) []string {
	ctx, cancel := context.WithTimeout(context.Background(), completionTimeout)
	defer cancel()
	stage := stageOf(cmd)
	c, err := newClient(ctx, stage)
	if err != nil {
		return nil
	}
	env := ""
	if onlyStage && stage != "" {
		partner, _ := cmd.Flags().GetString("partner")
		if env, err = resolveEnv(ctx, c, partner, stage); err != nil {
			return nil
		}
	}
	l, err := c.ListDevices(ctx, env)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(l.Devices))
	for _, d := range l.Devices {
		out = append(out, d.ID+"\t"+d.Env+" "+string(d.Status))
	}
	return out
}

// completeLabel offers the label keys the docs use; the value is free text.
func completeLabel(_ *cobra.Command, _ []string, typed string) ([]string, cobra.ShellCompDirective) {
	if strings.Contains(typed, "=") {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return []string{"board=", "owner=", "note="}, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
}

// completeAWSProfile reads profile names out of ~/.aws/config and
// ~/.aws/credentials.
func completeAWSProfile(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	seen := map[string]bool{}
	files := []string{filepath.Join(home, ".aws", "config"), filepath.Join(home, ".aws", "credentials")}
	if p := os.Getenv("AWS_CONFIG_FILE"); p != "" {
		files[0] = p
	}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
				continue
			}
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			name = strings.TrimPrefix(name, "profile ")
			if name != "" && !strings.HasPrefix(name, "sso-session ") {
				seen[name] = true
			}
		}
		f.Close()
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, cobra.ShellCompDirectiveNoFileComp
}

var completeRegion = fixed(
	"us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1",
	"eu-west-1", "eu-west-2", "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
)

// completeSerialPort lists the USB serial devices an ESP32-S3 fixture shows
// up as on Linux and macOS.
func completeSerialPort(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	var out []string
	for _, pattern := range []string{"/dev/ttyUSB*", "/dev/ttyACM*", "/dev/cu.usbserial*", "/dev/cu.usbmodem*", "/dev/cu.wchusbserial*"} {
		m, _ := filepath.Glob(pattern)
		out = append(out, m...)
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeDay offers the last week of UTC days, newest first.
func completeDay(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	now := time.Now().UTC()
	out := make([]string, 7)
	for i := range out {
		out[i] = now.AddDate(0, 0, -i).Format("2006-01-02")
	}
	return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveKeepOrder
}

// completeStation suggests $ADL_STATION or the host name.
func completeStation(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	if s := os.Getenv("ADL_STATION"); s != "" {
		return []string{s}, cobra.ShellCompDirectiveNoFileComp
	}
	if h, err := os.Hostname(); err == nil {
		return []string{h}, cobra.ShellCompDirectiveNoFileComp
	}
	return nil, cobra.ShellCompDirectiveNoFileComp
}

// register attaches completion functions to flags by name. It panics on a
// typo so a missing completion shows up in the tests, not in a shell.
func register(cmd *cobra.Command, funcs map[string]completeFunc) {
	for name, fn := range funcs {
		if err := cmd.RegisterFlagCompletionFunc(name, fn); err != nil {
			panic(cmd.Name() + ": " + err.Error())
		}
	}
}
