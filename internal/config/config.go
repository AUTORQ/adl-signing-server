// Package config reads the server configuration from the environment. The
// Terraform modules set exactly these variables on the Lambda function and
// in the EC2 instance's systemd unit.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/AUTORQ/adl-signing-server/internal/auth"
	"github.com/AUTORQ/adl-signing-server/internal/service"
)

// Environment is one entry of ADL_ENVIRONMENTS.
type Environment struct {
	Name             string `json:"name"`
	Partner          string `json:"partner,omitempty"`
	Stage            string `json:"stage,omitempty"`
	Organization     string `json:"organization,omitempty"`
	KMSKeyID         string `json:"kms_key_id"`
	DevicePrefix     string `json:"device_prefix"`
	DeviceIDDigits   int    `json:"device_id_digits,omitempty"`
	DeviceIDFromChip bool   `json:"device_id_from_chip,omitempty"`
	ValidityDays     int    `json:"validity_days"`
	AllowKeyEscrow   bool   `json:"allow_key_escrow"`
	RequireChipID    bool   `json:"require_chip_id,omitempty"`
	CRLValidityHrs   int    `json:"crl_validity_hours,omitempty"`
}

type Server struct {
	ListenAddr      string
	Region          string
	TableName       string
	ArchiveBucket   string
	DataKMSKeyID    string
	EscrowKMSKeyID  string
	Environments    []Environment
	Organization    string
	DeviceIDPattern *regexp.Regexp
	AuthAudience    string
	AuthSTSRegions  []string
	AuthPolicy      *auth.Policy
	LogLevel        string
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// Load reads and validates the configuration.
func Load() (*Server, error) {
	c := &Server{
		ListenAddr:     getenv("ADL_LISTEN_ADDR", "127.0.0.1:8080"),
		Region:         getenv("AWS_REGION", getenv("AWS_DEFAULT_REGION", "")),
		TableName:      os.Getenv("ADL_TABLE_NAME"),
		ArchiveBucket:  os.Getenv("ADL_ARCHIVE_BUCKET"),
		DataKMSKeyID:   os.Getenv("ADL_DATA_KMS_KEY_ID"),
		EscrowKMSKeyID: os.Getenv("ADL_ESCROW_KMS_KEY_ID"),
		Organization:   os.Getenv("ADL_CERT_ORGANIZATION"),
		AuthAudience:   os.Getenv("ADL_AUTH_AUDIENCE"),
		LogLevel:       getenv("ADL_LOG_LEVEL", "info"),
	}
	var problems []string
	need := func(name, v string) {
		if v == "" {
			problems = append(problems, name+" is required")
		}
	}
	need("AWS_REGION", c.Region)
	need("ADL_TABLE_NAME", c.TableName)
	need("ADL_ARCHIVE_BUCKET", c.ArchiveBucket)
	need("ADL_DATA_KMS_KEY_ID", c.DataKMSKeyID)
	need("ADL_AUTH_AUDIENCE", c.AuthAudience)

	if p := os.Getenv("ADL_DEVICE_ID_PATTERN"); p != "" {
		re, err := regexp.Compile(p)
		if err != nil {
			problems = append(problems, "ADL_DEVICE_ID_PATTERN: "+err.Error())
		}
		c.DeviceIDPattern = re
	}

	regions := getenv("ADL_AUTH_STS_REGIONS", c.Region)
	for _, r := range strings.Split(regions, ",") {
		if r = strings.TrimSpace(r); r != "" {
			c.AuthSTSRegions = append(c.AuthSTSRegions, r)
		}
	}

	envJSON := os.Getenv("ADL_ENVIRONMENTS")
	if envJSON == "" {
		problems = append(problems, "ADL_ENVIRONMENTS is required")
	} else if err := strictJSON(envJSON, &c.Environments); err != nil {
		problems = append(problems, "ADL_ENVIRONMENTS: "+err.Error())
	}
	escrow := false
	for _, e := range c.Environments {
		if e.Name == "" || e.KMSKeyID == "" || e.DevicePrefix == "" || e.ValidityDays <= 0 {
			problems = append(problems, fmt.Sprintf("ADL_ENVIRONMENTS: %q needs name, kms_key_id, device_prefix and validity_days", e.Name))
		}
		escrow = escrow || e.AllowKeyEscrow
	}
	if escrow && c.EscrowKMSKeyID == "" {
		problems = append(problems, "ADL_ESCROW_KMS_KEY_ID is required when any environment allows key escrow")
	}

	polJSON := os.Getenv("ADL_AUTH_POLICY")
	if polJSON == "" {
		problems = append(problems, "ADL_AUTH_POLICY is required")
	} else {
		c.AuthPolicy = &auth.Policy{}
		if err := strictJSON(polJSON, c.AuthPolicy); err != nil {
			problems = append(problems, "ADL_AUTH_POLICY: "+err.Error())
		} else if err := c.AuthPolicy.Validate(); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return nil, errors.New("invalid configuration:\n  " + strings.Join(problems, "\n  "))
	}
	return c, nil
}

// ServiceEnvs converts to the service's environment config.
func (c *Server) ServiceEnvs() []service.EnvConfig {
	out := make([]service.EnvConfig, 0, len(c.Environments))
	for _, e := range c.Environments {
		out = append(out, service.EnvConfig{
			Name: e.Name, Partner: e.Partner, Stage: e.Stage, Organization: e.Organization,
			DevicePrefix: e.DevicePrefix, DeviceIDDigits: e.DeviceIDDigits, DeviceIDFromChip: e.DeviceIDFromChip,
			Validity:       time.Duration(e.ValidityDays) * 24 * time.Hour,
			AllowKeyEscrow: e.AllowKeyEscrow,
			RequireChipID:  e.RequireChipID,
			CRLValidity:    time.Duration(e.CRLValidityHrs) * time.Hour,
		})
	}
	return out
}

// KMSKey returns the CA key for env.
func (c *Server) KMSKey(env string) (string, bool) {
	for _, e := range c.Environments {
		if e.Name == env {
			return e.KMSKeyID, true
		}
	}
	return "", false
}

func strictJSON(s string, v any) error {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
