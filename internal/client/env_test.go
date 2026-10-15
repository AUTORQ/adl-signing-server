package client

import (
	"strings"
	"testing"

	"github.com/edge-labs/adl-signing-server/internal/model"
)

func TestResolveEnv(t *testing.T) {
	edge := []model.EnvAccess{
		{Name: "edge-labs-dev", Partner: "edge-labs", Stage: "dev"},
		{Name: "edge-labs-prod", Partner: "edge-labs", Stage: "prod"},
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
		{"partner staff only name the stage", edge, "", "dev", "edge-labs-dev", ""},
		{"full names work too", edge, "", "edge-labs-prod", "edge-labs-prod", ""},
		{"someone acting for several partners must pick", staff, "", "dev", "", "--partner"},
		{"and then gets that partner's", staff, "acme", "prod", "acme-prod", ""},
		{"a partner you cannot act for", edge, "acme", "dev", "", "acting for acme"},
		{"another partner's full name is refused", edge, "", "acme-dev", "", "cannot use acme-dev"},
		{"partner and full name must agree", staff, "acme", "edge-labs-dev", "", "cannot use"},
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
