package client

import (
	"fmt"
	"slices"
	"strings"

	"github.com/edge-labs/adl-signing-server/internal/model"
)

// ResolveEnv turns what someone typed into an environment name. want is a
// stage (dev, prod) or a full environment name (edge-labs-dev); partner
// picks between partners for people who may act for several. access is
// what /v1/whoami says the caller may use, so a partner's people get their
// own environment from just "dev" without ever naming the partner.
func ResolveEnv(access []model.EnvAccess, partner, want string) (string, error) {
	if want == "" {
		return "", fmt.Errorf("no environment given")
	}
	var matches []model.EnvAccess
	for _, e := range access {
		if partner != "" && e.Partner != partner {
			continue
		}
		if e.Name == want {
			return e.Name, nil
		}
		if e.Stage == want {
			matches = append(matches, e)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].Name, nil
	case 0:
		who := "you"
		if partner != "" {
			who = "you, acting for " + partner + ","
		}
		return "", fmt.Errorf("%s cannot use %s (environments you can use: %s)", who, want, describe(access))
	}
	var partners []string
	for _, m := range matches {
		partners = append(partners, m.Partner)
	}
	slices.Sort(partners)
	return "", fmt.Errorf("you can act for several partners in %s (%s): pass --partner, or set a default with `adl configure --partner`",
		want, strings.Join(slices.Compact(partners), ", "))
}

// PartnerEnvs lists the environments of one partner the caller may use.
func PartnerEnvs(access []model.EnvAccess, partner string) []string {
	var out []string
	for _, e := range access {
		if e.Partner == partner {
			out = append(out, e.Name)
		}
	}
	return out
}

func describe(access []model.EnvAccess) string {
	if len(access) == 0 {
		return "none"
	}
	names := make([]string, 0, len(access))
	for _, e := range access {
		names = append(names, e.Name)
	}
	return strings.Join(names, ", ")
}
