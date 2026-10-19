package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/AUTORQ/adl-signing-server/internal/config"
)

// These are the variables the Terraform core module emits.
func setValid(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("ADL_TABLE_NAME", "adl-signer-registry")
	t.Setenv("ADL_ARCHIVE_BUCKET", "adl-signer-archive")
	t.Setenv("ADL_DATA_KMS_KEY_ID", "arn:aws:kms:us-east-1:123456789012:key/data")
	t.Setenv("ADL_ESCROW_KMS_KEY_ID", "arn:aws:kms:us-east-1:123456789012:key/escrow")
	t.Setenv("ADL_AUTH_AUDIENCE", "adl-signing-server:123456789012")
	t.Setenv("ADL_ENVIRONMENTS", `[
		{"name":"dev","kms_key_id":"arn:dev","device_prefix":"GLXADL","device_id_digits":3,"validity_days":3650,"allow_key_escrow":true,"crl_validity_hours":168},
		{"name":"prod","kms_key_id":"arn:prod","device_prefix":"GLXADL","device_id_digits":3,"validity_days":3650,"allow_key_escrow":false,"require_chip_id":true,"crl_validity_hours":168}
	]`)
	t.Setenv("ADL_AUTH_POLICY", `{"accounts":["123456789012"],"bindings":[{"roles":["adl-developer"],"users":[],"permissions":["dev:issue","dev:read"]}]}`)
}

func TestLoad(t *testing.T) {
	setValid(t)
	c, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := c.KMSKey("prod"); !ok || k != "arn:prod" {
		t.Errorf("prod key %q", k)
	}
	envs := c.ServiceEnvs()
	if len(envs) != 2 || !envs[0].AllowKeyEscrow || envs[1].AllowKeyEscrow || !envs[1].RequireChipID || envs[0].Validity != 3650*24*time.Hour {
		t.Errorf("envs %+v", envs)
	}
	if len(c.AuthSTSRegions) != 1 || c.AuthSTSRegions[0] != "us-east-1" {
		t.Errorf("sts regions default %v", c.AuthSTSRegions)
	}
	if c.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("listen default %q", c.ListenAddr)
	}
}

func TestLoadRejectsBadConfig(t *testing.T) {
	cases := map[string]func(t *testing.T){
		"missing table":    func(t *testing.T) { t.Setenv("ADL_TABLE_NAME", "") },
		"typo in env json": func(t *testing.T) { t.Setenv("ADL_ENVIRONMENTS", `[{"name":"dev","kms_keyid":"x"}]`) },
		"bad permission": func(t *testing.T) {
			t.Setenv("ADL_AUTH_POLICY", `{"accounts":["123456789012"],"bindings":[{"roles":["r"],"permissions":["root"]}]}`)
		},
		"no accounts":        func(t *testing.T) { t.Setenv("ADL_AUTH_POLICY", `{"accounts":[],"bindings":[]}`) },
		"escrow without key": func(t *testing.T) { t.Setenv("ADL_ESCROW_KMS_KEY_ID", "") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			setValid(t)
			mutate(t)
			_, err := config.Load()
			if err == nil || !strings.Contains(err.Error(), "invalid configuration") {
				t.Fatalf("expected config error, got %v", err)
			}
		})
	}
}

// The shape the AutorQ Terraform stack emits for a shared deployment.
func TestLoadPartners(t *testing.T) {
	setValid(t)
	t.Setenv("ADL_ENVIRONMENTS", `[
		{"name":"globex-dev","partner":"globex","stage":"dev","organization":"Globex","kms_key_id":"arn:a","device_prefix":"GLXADL","device_id_from_chip":true,"validity_days":3650,"allow_key_escrow":true}
	]`)
	t.Setenv("ADL_AUTH_POLICY", `{"accounts":["123456789012","222222222222"],"bindings":[{"accounts":["222222222222"],"roles":["*"],"users":["*"],"permissions":["globex-dev:issue"]}]}`)
	c, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	e := c.ServiceEnvs()[0]
	if e.Partner != "globex" || e.Stage != "dev" || e.Organization != "Globex" || !e.DeviceIDFromChip {
		t.Errorf("env %+v", e)
	}
	if b := c.AuthPolicy.Bindings[0]; len(b.Accounts) != 1 || b.Accounts[0] != "222222222222" {
		t.Errorf("binding %+v", b)
	}
}
