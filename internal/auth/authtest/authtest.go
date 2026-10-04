// Package authtest provides a fake STS endpoint that checks SigV4 signatures
// the same way the real one does, for tests that exercise real auth.
package authtest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

const (
	AccessKeyID = "AKIDEXAMPLE"
	Secret      = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	Account     = "111111111111"
)

// STS is a fake STS server. ARN decides who the caller "is"; change it
// between requests to switch identities.
type STS struct {
	*httptest.Server
	mu  sync.Mutex
	arn string
}

func NewSTS(arn string) *STS {
	s := &STS{arn: arn}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *STS) SetARN(arn string) {
	s.mu.Lock()
	s.arn = arn
	s.mu.Unlock()
}

// Endpoint is suitable for TokenSigner.Endpoint and STSVerifier.Endpoint.
func (s *STS) Endpoint(string) string { return s.URL + "/" }

// Credentials are the static credentials this fake accepts.
func Credentials() aws.CredentialsProvider {
	return credentials.NewStaticCredentialsProvider(AccessKeyID, Secret, "session-token")
}

func (s *STS) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if string(body) != "Action=GetCallerIdentity&Version=2011-06-15" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	authz := r.Header.Get("Authorization")
	i := strings.Index(authz, "SignedHeaders=")
	if i < 0 {
		reject(w)
		return
	}
	signedList := authz[i+len("SignedHeaders="):]
	if j := strings.Index(signedList, ","); j >= 0 {
		signedList = signedList[:j]
	}
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
		aws.Credentials{AccessKeyID: AccessKeyID, SecretAccessKey: Secret, SessionToken: r.Header.Get("X-Amz-Security-Token")},
		check, hex.EncodeToString(sum[:]), "sts", "us-east-1", ts)
	if check.Header.Get("Authorization") != authz {
		reject(w)
		return
	}
	s.mu.Lock()
	arn := s.arn
	s.mu.Unlock()
	fmt.Fprintf(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>%s</Arn><UserId>AROAEXAMPLE:x</UserId><Account>%s</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`, arn, Account)
}

func reject(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, `<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>signature mismatch</Message></Error></ErrorResponse>`)
}
