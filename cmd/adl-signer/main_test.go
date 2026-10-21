package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func TestSignerFlagsComplete(t *testing.T) {
	root := newRootCommand()
	for _, c := range root.Commands() {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Value.Type() == "bool" || f.Name == "help" {
				return
			}
			if _, ok := c.GetFlagCompletionFunc(f.Name); !ok {
				t.Errorf("%s --%s has no completion", c.CommandPath(), f.Name)
			}
		})
	}
}

func TestSignerHasInstall(t *testing.T) {
	root := newRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"install", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "adl-signer install cli local") {
		t.Errorf("install help not specialised:\n%s", out.String())
	}
}

func TestLocalInsecureRefusesPublicAddress(t *testing.T) {
	root := newRootCommand()
	root.SetArgs([]string{"serve", "--local-insecure", "--listen", "0.0.0.0:8080"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback refusal, got %v", err)
	}
}
