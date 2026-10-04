package lambdahttp_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"

	"github.com/edge-labs/adl-signing-server/internal/auth"
	"github.com/edge-labs/adl-signing-server/internal/lambdahttp"
	"github.com/edge-labs/adl-signing-server/internal/localstack"
	"github.com/edge-labs/adl-signing-server/internal/model"
	"github.com/edge-labs/adl-signing-server/internal/pki"
)

func event(method, path, query, body string, b64 bool) events.APIGatewayV2HTTPRequest {
	ev := events.APIGatewayV2HTTPRequest{
		RawPath: path, RawQueryString: query, Body: body, IsBase64Encoded: b64,
		Headers: map[string]string{"content-type": "application/json", auth.HeaderLocalPrincipal: "lambda-test"},
	}
	ev.RequestContext.HTTP.Method = method
	ev.RequestContext.HTTP.SourceIP = "203.0.113.9"
	ev.RequestContext.RequestID = "apigw-request-id-123"
	ev.RequestContext.DomainName = "signer.example.com"
	return ev
}

func TestThroughLambdaAdapter(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := localstack.New(log)
	if err != nil {
		t.Fatal(err)
	}
	h := lambdahttp.Handler(st.Handler(&auth.Local{Permissions: []string{"*"}}, log))
	ctx := context.Background()

	key, _ := pki.GenerateKey("rsa2048")
	csr, _ := pki.CreateCSR(key, pkixName())
	body, _ := json.Marshal(model.IssueRequest{Env: "dev", CSR: string(csr)})
	// API Gateway may hand us the body base64 encoded.
	resp, err := h(ctx, event("POST", "/v1/devices", "", base64.StdEncoding.EncodeToString(body), true))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("status %d: %s", resp.StatusCode, resp.Body)
	}
	if resp.Headers["X-Request-Id"] != "apigw-request-id-123" {
		t.Errorf("request id not propagated: %v", resp.Headers)
	}
	var out model.IssueResponse
	if err := json.Unmarshal([]byte(resp.Body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Device.Owner != "lambda-test" {
		t.Errorf("owner %q", out.Device.Owner)
	}

	resp, _ = h(ctx, event("GET", "/v1/devices", "env=dev", "", false))
	if resp.StatusCode != 200 || !strings.Contains(resp.Body, out.Device.ID) {
		t.Errorf("list: %d %s", resp.StatusCode, resp.Body)
	}

	// CRL is binary and must come back base64 encoded.
	resp, _ = h(ctx, event("GET", "/v1/ca/dev/crl", "", "", false))
	if resp.StatusCode != 200 || !resp.IsBase64Encoded {
		t.Fatalf("crl: %d b64=%v", resp.StatusCode, resp.IsBase64Encoded)
	}
	der, _ := base64.StdEncoding.DecodeString(resp.Body)
	if _, err := x509.ParseRevocationList(der); err != nil {
		t.Errorf("crl did not parse: %v", err)
	}

	resp, _ = h(ctx, event("GET", "/v1/nope", "", "", false))
	if resp.StatusCode != 404 {
		t.Errorf("unknown route: %d", resp.StatusCode)
	}
	resp, _ = h(ctx, event("POST", "/v1/devices", "", `{"env":"dev","csr":"x","surprise":1}`, false))
	if resp.StatusCode != 400 || !strings.Contains(resp.Body, "unknown field") {
		t.Errorf("unknown fields should be rejected: %d %s", resp.StatusCode, resp.Body)
	}
}

func pkixName() pkix.Name { return pkix.Name{CommonName: "pending"} }
