package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/edge-labs/adl-signing-server/internal/auth"
	"github.com/edge-labs/adl-signing-server/internal/store"
)

const (
	testAKID   = "AKIDEXAMPLE"
	testSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	testARN    = "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_ADLDeveloper_abc123/jane@autorq.com"
)

// fakeSTS verifies SigV4 exactly like STS would (re-signs with the known
// secret and compares) and answers with a fixed identity.
func fakeSTS(t *testing.T, arn string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != "Action=GetCallerIdentity&Version=2011-06-15" {
			http.Error(w, "bad body", 400)
			return
		}
		authz := r.Header.Get("Authorization")
		signedList := authz[strings.Index(authz, "SignedHeaders=")+len("SignedHeaders="):]
		signedList = signedList[:strings.Index(signedList, ",")]

		check, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), strings.NewReader(string(body)))
		for _, h := range strings.Split(signedList, ";") {
			if h == "host" || h == "content-length" {
				continue
			}
			check.Header.Set(h, r.Header.Get(h))
		}
		ts, _ := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		sum := sha256.Sum256(body)
		_ = v4.NewSigner().SignHTTP(context.Background(),
			aws.Credentials{AccessKeyID: testAKID, SecretAccessKey: testSecret, SessionToken: r.Header.Get("X-Amz-Security-Token")},
			check, hex.EncodeToString(sum[:]), "sts", "us-east-1", ts)
		if check.Header.Get("Authorization") != authz {
			w.WriteHeader(403)
			fmt.Fprint(w, `<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>nope</Message></Error></ErrorResponse>`)
			return
		}
		fmt.Fprintf(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>%s</Arn><UserId>AROA:jane</UserId><Account>111111111111</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`, arn)
	}))
}

func setup(t *testing.T, arn string) (*auth.TokenSigner, *auth.STSVerifier) {
	srv := fakeSTS(t, arn)
	t.Cleanup(srv.Close)
	endpoint := func(string) string { return srv.URL + "/" }
	signer := &auth.TokenSigner{
		Credentials: credentials.NewStaticCredentialsProvider(testAKID, testSecret, "session-token"),
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
	signer.Credentials = credentials.NewStaticCredentialsProvider(testAKID, "wrong-secret", "")
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
