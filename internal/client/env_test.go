package client

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AUTORQ/adl-signing-server/internal/model"
)

func TestResolveEnv(t *testing.T) {
	edge := []model.EnvAccess{
		{Name: "globex-dev", Partner: "globex", Stage: "dev"},
		{Name: "globex-prod", Partner: "globex", Stage: "prod"},
	}
	staff := append([]model.EnvAccess{
		{Name: "acme-dev", Partner: "acme", Stage: "dev"},
		{Name: "acme-prod", Partner: "acme", Stage: "prod"},
	}, edge...)
	single := []model.EnvAccess{{Name: "dev", Stage: "dev"}, {Name: "prod", Stage: "prod"}}

	for _, tc := range []struct {
		name            string
		access          []model.EnvAccess
		partner, want   string
		out, errContain string
	}{
		{"partner staff only name the stage", edge, "", "dev", "globex-dev", ""},
		{"full names work too", edge, "", "globex-prod", "globex-prod", ""},
		{"someone acting for several partners must pick", staff, "", "dev", "", "--partner"},
		{"and then gets that partner's", staff, "acme", "prod", "acme-prod", ""},
		{"a partner you cannot act for", edge, "acme", "dev", "", "acting for acme"},
		{"another partner's full name is refused", edge, "", "acme-dev", "", "cannot use acme-dev"},
		{"partner and full name must agree", staff, "acme", "globex-dev", "", "cannot use"},
		{"single tenant deployments", single, "", "prod", "prod", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveEnv(tc.access, tc.partner, tc.want)
			if tc.errContain != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errContain) {
					t.Fatalf("got %q, %v; want error containing %q", got, err, tc.errContain)
				}
				return
			}
			if err != nil || got != tc.out {
				t.Fatalf("got %q, %v; want %q", got, err, tc.out)
			}
		})
	}
}

func TestConfigForStage(t *testing.T) {
	c := &Config{Server: Server{Profile: "globex"}, Stages: map[string]*Server{
		"dev":  {URL: "https://signer.dev.autorq.com", Region: "us-east-1", Audience: "autorq-signer:dev"},
		"prod": {URL: "https://signer.prod.autorq.com", Region: "us-east-1", Audience: "autorq-signer:prod", Profile: "globex-prod"},
	}}
	for want, url := range map[string]string{
		"dev": "https://signer.dev.autorq.com", "globex-dev": "https://signer.dev.autorq.com",
		"prod": "https://signer.prod.autorq.com", "acme-prod": "https://signer.prod.autorq.com",
	} {
		got, err := c.ForStage(want)
		if err != nil || got.URL != url {
			t.Errorf("%s: %+v %v", want, got, err)
		}
	}
	if got, _ := c.ForStage("dev"); got.Profile != "globex" {
		t.Errorf("dev inherits the default profile, got %q", got.Profile)
	}
	if got, _ := c.ForStage("prod"); got.Profile != "globex-prod" {
		t.Errorf("prod keeps its own profile, got %q", got.Profile)
	}
	if _, err := c.ForStage(""); err == nil || !strings.Contains(err.Error(), "--stage") {
		t.Errorf("no default server: %v", err)
	}
	if _, err := c.ForStage("staging"); err == nil {
		t.Error("unknown stage without a default server")
	}
	c.URL = "https://signer.example"
	if got, err := c.ForStage("staging"); err != nil || got.URL != "https://signer.example" {
		t.Errorf("falls back to the default server: %+v %v", got, err)
	}
}

// Configs written before stages existed still load the same.
func TestConfigFormatUnchanged(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"url":"https://x","region":"us-east-1","audience":"a","profile":"p"}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.URL != "https://x" || c.Profile != "p" {
		t.Errorf("%+v", c)
	}
}
