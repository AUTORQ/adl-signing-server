package pki

import (
	"fmt"
	"sort"
)

// RFC 5280 CRLReason codes that make sense for device certificates.
var revocationReasons = map[string]int{
	"unspecified":          0,
	"keyCompromise":        1,
	"affiliationChanged":   3,
	"superseded":           4,
	"cessationOfOperation": 5,
}

// ReasonCode maps a reason name to its CRL code.
func ReasonCode(name string) (int, error) {
	if name == "" {
		return 0, nil
	}
	code, ok := revocationReasons[name]
	if !ok {
		return 0, fmt.Errorf("unknown revocation reason %q (valid: %v)", name, ReasonNames())
	}
	return code, nil
}

// ReasonNames lists the accepted reason names.
func ReasonNames() []string {
	out := make([]string, 0, len(revocationReasons))
	for k := range revocationReasons {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
