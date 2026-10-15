// Package auth identifies callers by their AWS IAM identity and maps them to
// permissions.
//
// Callers never send credentials to us. The CLI signs an sts:GetCallerIdentity
// request with its own AWS credentials and passes the signed headers along;
// the server replays that request to STS and trusts whatever identity STS
// reports. The signature covers an audience header (so a token minted for this
// service is useless anywhere else), a nonce, and a digest of the exact API
// request (so a captured token cannot be attached to a different request).
// This is the same approach Vault's AWS auth method uses.
package auth

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrNotAuthorized   = errors.New("principal is not authorized to use this service")
)

// Principal is an authenticated caller.
type Principal struct {
	ARN     string
	Account string
	// Kind is "assumed-role", "user" or "local".
	Kind string
	// Role is the IAM role name for assumed-role principals.
	Role string
	// Session is the role session name. For IAM Identity Center this is
	// the person's username, which is what ends up in the audit log.
	Session     string
	User        string
	Permissions []string
}

// Name is a short human readable identity for logs and the registry.
func (p *Principal) Name() string {
	switch p.Kind {
	case "assumed-role":
		return p.Role + "/" + p.Session
	case "user":
		return "user/" + p.User
	}
	return p.Session
}

// Can reports whether p holds perm, honouring "*" and "env:*" grants.
func (p *Principal) Can(perm string) bool {
	if p == nil {
		return false
	}
	for _, g := range p.Permissions {
		if g == "*" || g == perm {
			return true
		}
		if prefix, ok := strings.CutSuffix(g, "*"); ok && strings.HasPrefix(perm, prefix) {
			return true
		}
	}
	return false
}

var arnRE = regexp.MustCompile(`^arn:aws[a-z-]*:(sts|iam)::(\d{12}):(.+)$`)

// ParseARN turns a GetCallerIdentity ARN into a Principal without permissions.
func ParseARN(arn string) (*Principal, error) {
	m := arnRE.FindStringSubmatch(arn)
	if m == nil {
		return nil, fmt.Errorf("unrecognised caller arn %q", arn)
	}
	svc, account, res := m[1], m[2], m[3]
	p := &Principal{ARN: arn, Account: account}
	switch {
	case svc == "sts" && strings.HasPrefix(res, "assumed-role/"):
		parts := strings.SplitN(strings.TrimPrefix(res, "assumed-role/"), "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("malformed assumed-role arn %q", arn)
		}
		p.Kind, p.Role, p.Session = "assumed-role", parts[0], parts[1]
	case svc == "iam" && strings.HasPrefix(res, "user/"):
		name := res[strings.LastIndex(res, "/")+1:]
		if name == "" {
			return nil, fmt.Errorf("malformed user arn %q", arn)
		}
		p.Kind, p.User = "user", name
	default:
		// Root, federated users and anything else are refused outright.
		return nil, fmt.Errorf("caller type in %q is not allowed", arn)
	}
	return p, nil
}

// Policy maps IAM identities to permissions.
//
// Permissions are "<env>:<action>" where action is one of issue, read,
// key-read, provision, revoke; or the global "ca:admin", "audit:read",
// "admin:import". "dev:*" and "*" are wildcards.
type Policy struct {
	// Accounts limits which AWS accounts may call at all. Required.
	Accounts []string  `json:"accounts"`
	Bindings []Binding `json:"bindings"`
}

// Binding grants permissions to roles and/or users matching glob patterns.
// Role patterns let you match IAM Identity Center roles such as
// "AWSReservedSSO_ADLDeveloper_*".
//
// Accounts, when set, limits the binding to callers from those accounts.
// Role names are only unique within an account, so a deployment shared by
// several organisations (one AWS account per manufacturing partner) should
// scope every binding: otherwise a partner could create a role named like
// an AutorQ admin's in their own account and match its binding.
type Binding struct {
	Accounts    []string `json:"accounts,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Users       []string `json:"users,omitempty"`
	Permissions []string `json:"permissions"`
}

// ReservedNames are permission namespaces that can't be environment names,
// otherwise "ca:*" would read as an env wildcard and grant ca:admin.
var ReservedNames = []string{"ca", "admin", "audit"}

var (
	accountRE   = regexp.MustCompile(`^\d{12}$`)
	envActionRE = regexp.MustCompile(`^[a-z][a-z0-9-]*:(\*|issue|read|key-read|provision|revoke)$`)
	globalPerms = []string{"*", "ca:admin", "audit:read", "admin:import"}
)

// Validate checks the policy is well formed.
func (p *Policy) Validate() error {
	if len(p.Accounts) == 0 {
		return errors.New("auth policy: at least one account is required")
	}
	for _, a := range p.Accounts {
		if !accountRE.MatchString(a) {
			return fmt.Errorf("auth policy: bad account id %q", a)
		}
	}
	for i, b := range p.Bindings {
		if len(b.Roles) == 0 && len(b.Users) == 0 {
			return fmt.Errorf("auth policy: binding %d has no roles or users", i)
		}
		for _, a := range b.Accounts {
			if !slices.Contains(p.Accounts, a) {
				return fmt.Errorf("auth policy: binding %d names account %q, which is not in accounts", i, a)
			}
		}
		for _, pat := range append(slices.Clone(b.Roles), b.Users...) {
			if _, err := path.Match(pat, ""); err != nil {
				return fmt.Errorf("auth policy: bad pattern %q: %w", pat, err)
			}
		}
		for _, perm := range b.Permissions {
			if slices.Contains(globalPerms, perm) {
				continue
			}
			env, _, _ := strings.Cut(perm, ":")
			if !envActionRE.MatchString(perm) || slices.Contains(ReservedNames, env) {
				return fmt.Errorf("auth policy: unknown permission %q", perm)
			}
		}
	}
	return nil
}

// Resolve fills in p.Permissions. It returns ErrNotAuthorized if the account
// is not allowed or nothing matched.
func (pol *Policy) Resolve(p *Principal) error {
	if !slices.Contains(pol.Accounts, p.Account) {
		return fmt.Errorf("%w: account %s not allowed", ErrNotAuthorized, p.Account)
	}
	var perms []string
	for _, b := range pol.Bindings {
		if len(b.Accounts) > 0 && !slices.Contains(b.Accounts, p.Account) {
			continue
		}
		var patterns []string
		var subject string
		switch p.Kind {
		case "assumed-role":
			patterns, subject = b.Roles, p.Role
		case "user":
			patterns, subject = b.Users, p.User
		}
		for _, pat := range patterns {
			if ok, _ := path.Match(pat, subject); ok {
				perms = append(perms, b.Permissions...)
				break
			}
		}
	}
	if len(perms) == 0 {
		return fmt.Errorf("%w: no binding for %s", ErrNotAuthorized, p.ARN)
	}
	slices.Sort(perms)
	p.Permissions = slices.Compact(perms)
	return nil
}
