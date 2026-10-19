package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/AUTORQ/adl-signing-server/internal/auth"
	"github.com/AUTORQ/adl-signing-server/internal/auth/authtest"
	"github.com/AUTORQ/adl-signing-server/internal/store"
)

const testARN = "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_ADLDeveloper_abc123/jane@autorq.com"

func setup(t *testing.T, arn string) (*auth.TokenSigner, *auth.STSVerifier) {
	srv := authtest.NewSTS(arn)
	t.Cleanup(srv.Close)
	endpoint := srv.Endpoint
	signer := &auth.TokenSigner{
		Credentials: authtest.Credentials(),
		Region:      "us-east-1",
		Audience:    "adl-signing-server",
		Endpoint:    endpoint,
	}
	verifier := &auth.STSVerifier{
		Audience: "adl-signing-server",
		Regions:  []string{"us-east-1"},
		Endpoint: endpoint,
		Nonces:   store.NewMemory(),
		Policy: &auth.Policy{
			Accounts: []string{"111111111111"},
			Bindings: []auth.Binding{
				{Roles: []string{"AWSReservedSSO_ADLDeveloper_*"}, Permissions: []string{"dev:issue", "dev:read", "dev:key-read"}},
				{Roles: []string{"adl-factory-station"}, Permissions: []string{"prod:issue", "prod:provision", "prod:read"}},
			},
		},
	}
	return signer, verifier
}

func request(t *testing.T, signer *auth.TokenSigner, method, uri, body string) *http.Request {
	tok, err := signer.Token(context.Background(), method, uri, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, uri, strings.NewReader(body))
	r.Header.Set(auth.HeaderAuth, tok)
	return r
}

func TestRoundTrip(t *testing.T) {
	signer, verifier := setup(t, testARN)
	body := `{"env":"dev"}`
	r := request(t, signer, "POST", "/v1/devices", body)
	p, err := verifier.Authenticate(context.Background(), r, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "AWSReservedSSO_ADLDeveloper_abc123/jane@autorq.com" {
		t.Errorf("name %q", p.Name())
	}
	if !p.Can("dev:issue") || p.Can("prod:issue") {
		t.Errorf("unexpected permissions %v", p.Permissions)
	}

	// Same token again is a replay.
	if _, err := verifier.Authenticate(context.Background(), r, []byte(body)); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("replay accepted: %v", err)
	}
}

func TestTokenBoundToRequest(t *testing.T) {
	signer, verifier := setup(t, testARN)
	r := request(t, signer, "POST", "/v1/devices", `{"env":"dev"}`)
	// Attacker swaps the body.
	if _, err := verifier.Authenticate(context.Background(), r, []byte(`{"env":"prod"}`)); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("tampered body accepted: %v", err)
	}
	// Or the path.
	r2 := request(t, signer, "GET", "/v1/devices/A", "")
	r2.URL.Path = "/v1/devices/B"
	if _, err := verifier.Authenticate(context.Background(), r2, nil); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("tampered path accepted: %v", err)
	}
}

func TestAudienceAndSignature(t *testing.T) {
	signer, verifier := setup(t, testARN)
	signer.Audience = "some-other-service"
	r := request(t, signer, "GET", "/v1/whoami", "")
	if _, err := verifier.Authenticate(context.Background(), r, nil); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("wrong audience accepted: %v", err)
	}

	signer.Audience = "adl-signing-server"
	signer.Credentials = credentials.NewStaticCredentialsProvider(authtest.AccessKeyID, "wrong-secret", "")
	r = request(t, signer, "GET", "/v1/whoami", "")
	if _, err := verifier.Authenticate(context.Background(), r, nil); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("bad signature accepted: %v", err)
	}
}

func TestStaleToken(t *testing.T) {
	signer, verifier := setup(t, testARN)
	signer.Now = func() time.Time { return time.Now().Add(-10 * time.Minute) }
	r := request(t, signer, "GET", "/v1/whoami", "")
	if _, err := verifier.Authenticate(context.Background(), r, nil); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("stale token accepted: %v", err)
	}
}

func TestUnboundRoleRejected(t *testing.T) {
	signer, verifier := setup(t, "arn:aws:sts::111111111111:assumed-role/SomethingElse/bob")
	r := request(t, signer, "GET", "/v1/whoami", "")
	if _, err := verifier.Authenticate(context.Background(), r, nil); !errors.Is(err, auth.ErrNotAuthorized) {
		t.Errorf("expected not authorized, got %v", err)
	}
}

func TestParseARN(t *testing.T) {
	for _, bad := range []string{
		"arn:aws:iam::111111111111:root",
		"arn:aws:sts::111111111111:federated-user/bob",
		"arn:aws:sts::111111111111:assumed-role/OnlyRole",
		"nonsense",
	} {
		if _, err := auth.ParseARN(bad); err == nil {
			t.Errorf("%s should be rejected", bad)
		}
	}
	p, err := auth.ParseARN("arn:aws:iam::111111111111:user/ci/deployer")
	if err != nil || p.User != "deployer" {
		t.Errorf("user arn: %+v %v", p, err)
	}
}

func TestPolicyValidate(t *testing.T) {
	good := &auth.Policy{Accounts: []string{"111111111111"}, Bindings: []auth.Binding{{Roles: []string{"a*"}, Permissions: []string{"dev:*", "ca:admin", "prod:key-read"}}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := &auth.Policy{Accounts: []string{"111111111111"}, Bindings: []auth.Binding{{Roles: []string{"a"}, Permissions: []string{"dev:everything"}}}}
	if err := bad.Validate(); err == nil {
		t.Error("expected unknown permission error")
	}
}

func TestPrincipalCan(t *testing.T) {
	p := &auth.Principal{Permissions: []string{"dev:*", "audit:read"}}
	for perm, want := range map[string]bool{"dev:issue": true, "dev:key-read": true, "prod:issue": false, "audit:read": true, "ca:admin": false} {
		if p.Can(perm) != want {
			t.Errorf("Can(%s) = %v", perm, !want)
		}
	}
}

// TestRealSTS checks the signing format against the real STS endpoint using
// whatever AWS credentials are configured. It only calls GetCallerIdentity.
// Run with ADL_TEST_REAL_STS=1 (and AWS_PROFILE if needed).
func TestRealSTS(t *testing.T) {
	if os.Getenv("ADL_TEST_REAL_STS") == "" {
		t.Skip("ADL_TEST_REAL_STS not set")
	}
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	signer := &auth.TokenSigner{Credentials: cfg.Credentials, Region: region, Audience: "adl-test"}
	verifier := &auth.STSVerifier{Audience: "adl-test", Regions: []string{region}, Nonces: store.NewMemory(),
		Policy: &auth.Policy{Accounts: []string{"000000000000"}}}
	r := request(t, signer, "GET", "/v1/whoami", "")
	_, err = verifier.Authenticate(ctx, r, nil)
	// The account is deliberately not allowed, so success here means STS
	// accepted the signature and we got as far as the policy check.
	if !errors.Is(err, auth.ErrNotAuthorized) {
		t.Fatalf("expected STS to accept the token and policy to refuse it, got %v", err)
	}
	t.Log(err)
}

func TestDuplicateAuthorizationFieldsRejected(t *testing.T) {
	signer, verifier := setup(t, testARN)
	tok, err := signer.Token(context.Background(), "GET", "/v1/whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	hdrs := m["headers"].(map[string]any)
	hdrs["Authorization"] = hdrs["Authorization"].(string) + ", SignedHeaders=host;x-amz-date"
	raw, _ = json.Marshal(m)
	r := httptest.NewRequest("GET", "/v1/whoami", nil)
	r.Header.Set(auth.HeaderAuth, base64.RawURLEncoding.EncodeToString(raw))
	if _, err := verifier.Authenticate(context.Background(), r, nil); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("duplicate SignedHeaders accepted: %v", err)
	}
}

type brokenNonces struct{}

func (brokenNonces) ClaimNonce(context.Context, string, time.Time) error {
	return errors.New("ProvisionedThroughputExceededException")
}

func TestNonceStorageErrorIsNotReplay(t *testing.T) {
	signer, verifier := setup(t, testARN)
	verifier.Nonces = brokenNonces{}
	r := request(t, signer, "GET", "/v1/whoami", "")
	_, err := verifier.Authenticate(context.Background(), r, nil)
	if err == nil || errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("storage failure should be a server error, got %v", err)
	}
}

func TestReservedNamespacesNotEnvWildcards(t *testing.T) {
	for _, perm := range []string{"ca:*", "admin:*", "audit:*", "ca:issue"} {
		p := &auth.Policy{Accounts: []string{"111111111111"}, Bindings: []auth.Binding{{Roles: []string{"r"}, Permissions: []string{perm}}}}
		if err := p.Validate(); err == nil {
			t.Errorf("%s should be rejected", perm)
		}
	}
}

// One deployment for AutorQ and every manufacturing partner: the account a
// caller comes from decides which partner they act for. A partner creating
// a role named like an AutorQ admin's in their own account gets nothing
// more than their own environments.
func TestBindingsScopedToAccounts(t *testing.T) {
	const autorq, edge, acme = "111111111111", "222222222222", "333333333333"
	pol := &auth.Policy{
		Accounts: []string{autorq, edge, acme},
		Bindings: []auth.Binding{
			{Accounts: []string{autorq}, Roles: []string{"AWSReservedSSO_AdministratorAccess_*"}, Permissions: []string{"*"}},
			{Accounts: []string{edge}, Roles: []string{"*"}, Users: []string{"*"}, Permissions: []string{"globex-dev:issue", "globex-prod:issue"}},
			{Accounts: []string{acme}, Roles: []string{"*"}, Users: []string{"*"}, Permissions: []string{"acme-dev:issue"}},
		},
	}
	if err := pol.Validate(); err != nil {
		t.Fatal(err)
	}
	for arn, want := range map[string]string{
		"arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_AdministratorAccess_abc/thibault@autorq.com": "*",
		"arn:aws:iam::222222222222:user/john":                                                "globex-dev:issue globex-prod:issue",
		"arn:aws:sts::222222222222:assumed-role/AWSReservedSSO_AdministratorAccess_abc/eddy": "globex-dev:issue globex-prod:issue",
		"arn:aws:iam::333333333333:user/tony":                                                "acme-dev:issue",
		"arn:aws:iam::111111111111:user/someone":                                             "",
	} {
		p, err := auth.ParseARN(arn)
		if err != nil {
			t.Fatal(err)
		}
		err = pol.Resolve(p)
		if got := strings.Join(p.Permissions, " "); got != want || (want == "") != errors.Is(err, auth.ErrNotAuthorized) {
			t.Errorf("%s: got %q (%v), want %q", arn, got, err, want)
		}
	}

	pol.Bindings = append(pol.Bindings, auth.Binding{Accounts: []string{"444444444444"}, Roles: []string{"*"}, Permissions: []string{"acme-dev:read"}})
	if err := pol.Validate(); err == nil {
		t.Error("a binding for an account outside accounts must be refused")
	}
}
