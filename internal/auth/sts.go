package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/edge-labs/adl-signing-server/internal/store"
)

const (
	// HeaderAuth carries the signed STS request from client to server.
	HeaderAuth = "X-Adl-Auth"

	headerAudience = "X-Adl-Audience"
	headerDigest   = "X-Adl-Request-Digest"
	headerNonce    = "X-Adl-Nonce"

	stsBody        = "Action=GetCallerIdentity&Version=2011-06-15"
	stsContentType = "application/x-www-form-urlencoded; charset=utf-8"
	maxTokenSize   = 16 << 10
)

// RequestDigest binds a token to one API call.
func RequestDigest(method, requestURI string, body []byte) string {
	bh := sha256.Sum256(body)
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%x", strings.ToUpper(method), requestURI, bh)
	return hex.EncodeToString(h.Sum(nil))
}

// DefaultSTSEndpoint is the regional STS endpoint for the commercial
// partition.
func DefaultSTSEndpoint(region string) string {
	return "https://sts." + region + ".amazonaws.com/"
}

type token struct {
	Version int               `json:"v"`
	Region  string            `json:"region"`
	Headers map[string]string `json:"headers"`
}

// TokenSigner is the client half: it produces X-Adl-Auth header values.
type TokenSigner struct {
	Credentials aws.CredentialsProvider
	Region      string
	Audience    string
	// Endpoint overrides DefaultSTSEndpoint (GovCloud, China, tests).
	Endpoint func(region string) string
	Now      func() time.Time
}

// Token signs a GetCallerIdentity request bound to method/requestURI/body.
func (s *TokenSigner) Token(ctx context.Context, method, requestURI string, body []byte) (string, error) {
	if s.Region == "" || s.Audience == "" {
		return "", errors.New("auth: region and audience are required")
	}
	creds, err := s.Credentials.Retrieve(ctx)
	if err != nil {
		return "", fmt.Errorf("load aws credentials: %w", err)
	}
	endpoint := DefaultSTSEndpoint
	if s.Endpoint != nil {
		endpoint = s.Endpoint
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint(s.Region), strings.NewReader(stsBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", stsContentType)
	req.Header.Set(headerAudience, s.Audience)
	req.Header.Set(headerDigest, RequestDigest(method, requestURI, body))
	req.Header.Set(headerNonce, hex.EncodeToString(nonce))
	payload := sha256.Sum256([]byte(stsBody))
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(payload[:]), "sts", s.Region, now()); err != nil {
		return "", fmt.Errorf("sign sts request: %w", err)
	}

	tok := token{Version: 1, Region: s.Region, Headers: map[string]string{}}
	for k := range req.Header {
		tok.Headers[k] = req.Header.Get(k)
	}
	raw, err := json.Marshal(tok)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// NonceGuard remembers nonces so a token can only be used once.
type NonceGuard interface {
	// ClaimNonce returns an error if nonce was already claimed.
	ClaimNonce(ctx context.Context, nonce string, expires time.Time) error
}

// Authenticator is implemented by STSVerifier and Local.
type Authenticator interface {
	Authenticate(ctx context.Context, r *http.Request, body []byte) (*Principal, error)
}

// STSVerifier is the server half.
type STSVerifier struct {
	Audience string
	// Regions the client may sign for. The STS call goes to that region's
	// endpoint, so keep this to regions you actually use.
	Regions  []string
	Endpoint func(region string) string
	Policy   *Policy
	Nonces   NonceGuard
	HTTP     *http.Client
	MaxSkew  time.Duration
	Now      func() time.Time
	Log      *slog.Logger
}

func (v *STSVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *STSVerifier) fail(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnauthenticated, fmt.Sprintf(format, args...))
}

// Authenticate validates the X-Adl-Auth header on r. body must be the full
// request body (already read by the caller).
func (v *STSVerifier) Authenticate(ctx context.Context, r *http.Request, body []byte) (*Principal, error) {
	raw := r.Header.Get(HeaderAuth)
	if raw == "" {
		return nil, v.fail("missing %s header", HeaderAuth)
	}
	if len(raw) > maxTokenSize {
		return nil, v.fail("token too large")
	}
	dec, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, v.fail("token is not base64url")
	}
	var tok token
	if err := json.Unmarshal(dec, &tok); err != nil || tok.Version != 1 {
		return nil, v.fail("malformed token")
	}
	if !slices.Contains(v.Regions, tok.Region) {
		return nil, v.fail("region %q not accepted", tok.Region)
	}
	hdr := http.Header{}
	for k, val := range tok.Headers {
		hdr.Set(k, val)
	}

	signed, canonicalAuthz, err := checkAuthorization(hdr.Get("Authorization"), tok.Region)
	if err != nil {
		return nil, v.fail("%v", err)
	}
	hdr.Set("Authorization", canonicalAuthz)
	for _, need := range []string{"host", "x-amz-date", strings.ToLower(headerAudience), strings.ToLower(headerDigest), strings.ToLower(headerNonce)} {
		if !slices.Contains(signed, need) {
			return nil, v.fail("signature does not cover %s", need)
		}
	}
	if hdr.Get(headerAudience) != v.Audience {
		return nil, v.fail("token audience %q does not match this service", hdr.Get(headerAudience))
	}
	if hdr.Get(headerDigest) != RequestDigest(r.Method, r.URL.RequestURI(), body) {
		return nil, v.fail("token was signed for a different request")
	}
	ts, err := time.Parse("20060102T150405Z", hdr.Get("X-Amz-Date"))
	if err != nil {
		return nil, v.fail("bad X-Amz-Date")
	}
	skew := v.MaxSkew
	if skew == 0 {
		skew = 5 * time.Minute
	}
	if d := v.now().Sub(ts); d > skew || d < -skew {
		return nil, v.fail("token timestamp outside allowed skew")
	}
	nonce := hdr.Get(headerNonce)
	if len(nonce) < 16 {
		return nil, v.fail("nonce too short")
	}

	ident, err := v.callSTS(ctx, tok.Region, hdr, signed)
	if err != nil {
		return nil, err
	}

	// Only burn the nonce once STS has confirmed the signature, otherwise
	// anyone could pre-claim nonces with garbage tokens.
	if v.Nonces != nil {
		if err := v.Nonces.ClaimNonce(ctx, nonce, ts.Add(2*skew)); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return nil, v.fail("token already used")
			}
			return nil, fmt.Errorf("record auth nonce: %w", err)
		}
	}

	p, err := ParseARN(ident.Arn)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotAuthorized, err)
	}
	if p.Account != ident.Account {
		return nil, v.fail("sts account mismatch")
	}
	if err := v.Policy.Resolve(p); err != nil {
		return nil, err
	}
	return p, nil
}

var (
	signedHeadersRE = regexp.MustCompile(`^[a-z0-9-]+(;[a-z0-9-]+)*$`)
	signatureRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// checkAuthorization strictly parses a SigV4 Authorization header. It
// returns the signed header names and a canonical rebuild of the header,
// which is what we forward to STS. Rebuilding (rather than passing the
// caller's string through) means STS verifies exactly the fields we
// checked, and a duplicate or extra field can't be read one way by us
// and another way by STS.
func checkAuthorization(authz, region string) ([]string, string, error) {
	rest, ok := strings.CutPrefix(authz, "AWS4-HMAC-SHA256 ")
	if !ok {
		return nil, "", errors.New("authorization is not AWS4-HMAC-SHA256")
	}
	fields := map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return nil, "", errors.New("malformed authorization field")
		}
		switch k {
		case "Credential", "SignedHeaders", "Signature":
		default:
			return nil, "", fmt.Errorf("unexpected authorization field %q", k)
		}
		if _, dup := fields[k]; dup {
			return nil, "", fmt.Errorf("duplicate authorization field %q", k)
		}
		fields[k] = v
	}
	cred, signed, sig := fields["Credential"], fields["SignedHeaders"], fields["Signature"]
	scope := strings.Split(cred, "/")
	if len(scope) != 5 || scope[0] == "" || scope[2] != region || scope[3] != "sts" || scope[4] != "aws4_request" {
		return nil, "", errors.New("credential scope is not sts in the token region")
	}
	if !signedHeadersRE.MatchString(signed) {
		return nil, "", errors.New("bad signed headers list")
	}
	if !signatureRE.MatchString(sig) {
		return nil, "", errors.New("bad signature")
	}
	canonical := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s", cred, signed, sig)
	return strings.Split(signed, ";"), canonical, nil
}

type callerIdentity struct {
	Arn     string `xml:"GetCallerIdentityResult>Arn"`
	UserID  string `xml:"GetCallerIdentityResult>UserId"`
	Account string `xml:"GetCallerIdentityResult>Account"`
}

type stsError struct {
	Code    string `xml:"Error>Code"`
	Message string `xml:"Error>Message"`
}

func (v *STSVerifier) callSTS(ctx context.Context, region string, hdr http.Header, signed []string) (*callerIdentity, error) {
	endpoint := DefaultSTSEndpoint
	if v.Endpoint != nil {
		endpoint = v.Endpoint
	}
	// The URL and body are ours, never the caller's: this is what stops
	// the token being used to make us call somewhere else.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint(region), strings.NewReader(stsBody))
	if err != nil {
		return nil, err
	}
	for _, name := range signed {
		switch name {
		case "host", "content-length":
			continue
		}
		val := hdr.Get(name)
		if val == "" {
			return nil, v.fail("signed header %s missing from token", name)
		}
		req.Header.Set(name, val)
	}
	req.Header.Set("Authorization", hdr.Get("Authorization"))

	client := v.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call sts: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("read sts response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var se stsError
		_ = xml.Unmarshal(data, &se)
		if v.Log != nil {
			v.Log.WarnContext(ctx, "sts rejected caller token", "status", resp.StatusCode, "code", se.Code, "message", se.Message)
		}
		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("sts unavailable: %d %s", resp.StatusCode, se.Code)
		}
		return nil, v.fail("sts rejected token: %s", se.Code)
	}
	var ident callerIdentity
	if err := xml.Unmarshal(data, &ident); err != nil || ident.Arn == "" {
		return nil, fmt.Errorf("unexpected sts response")
	}
	return &ident, nil
}

// Local trusts an X-Adl-Local-Principal header. It exists for running the
// whole stack on a laptop and is refused unless the server listens on
// loopback.
type Local struct {
	Permissions []string
}

const HeaderLocalPrincipal = "X-Adl-Local-Principal"

func (l *Local) Authenticate(_ context.Context, r *http.Request, _ []byte) (*Principal, error) {
	name := r.Header.Get(HeaderLocalPrincipal)
	if name == "" {
		name = "local-user"
	}
	return &Principal{
		ARN: "local:" + name, Account: "000000000000", Kind: "local",
		Session: name, Permissions: slices.Clone(l.Permissions),
	}, nil
}
