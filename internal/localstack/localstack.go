// Package localstack assembles a complete signing server in memory: fake KMS
// keys, a throwaway root per environment, in-memory registry and archive.
// It backs `adl-signer serve --local-insecure` and the end-to-end tests.
// Nothing here is safe for real devices.
package localstack

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/AUTORQ/adl-signing-server/internal/api"
	"github.com/AUTORQ/adl-signing-server/internal/archive"
	"github.com/AUTORQ/adl-signing-server/internal/auth"
	"github.com/AUTORQ/adl-signing-server/internal/kmssigner"
	"github.com/AUTORQ/adl-signing-server/internal/model"
	"github.com/AUTORQ/adl-signing-server/internal/pki"
	"github.com/AUTORQ/adl-signing-server/internal/pki/pkitest"
	"github.com/AUTORQ/adl-signing-server/internal/service"
	"github.com/AUTORQ/adl-signing-server/internal/store"
)

type Stack struct {
	Service *service.Service
	Store   *store.Memory
	Archive *archive.Memory
	Roots   map[string]*x509.Certificate
}

// Envs mirrors deploy/terraform/environments/example/terraform.tfvars.example.
var Envs = []service.EnvConfig{
	{Name: "dev", DevicePrefix: "GLXADL", Validity: 3650 * 24 * time.Hour, AllowKeyEscrow: true},
	{Name: "prod", DevicePrefix: "GLXADL", Validity: 3650 * 24 * time.Hour, RequireChipID: true},
}

// New builds the stack and runs the CA ceremony for every environment.
func New(log *slog.Logger) (*Stack, error) {
	st := &Stack{Store: store.NewMemory(), Archive: archive.NewMemory(), Roots: map[string]*x509.Certificate{}}
	keys := map[string]crypto.Signer{}
	for _, e := range Envs {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		keys[e.Name] = k
	}
	factory := func(ctx context.Context, env string) (crypto.Signer, error) {
		k, ok := keys[env]
		if !ok {
			return nil, fmt.Errorf("no key for %s", env)
		}
		return kmssigner.New(ctx, &kmssigner.Fake{Key: k, ID: "local-" + env}, "local-"+env)
	}
	svc, err := service.New(service.Options{
		Store: st.Store, Archive: st.Archive, CAs: service.NewCAs(factory, st.Archive, nil),
		Envs: Envs, Organization: "Globex", Log: log,
	})
	if err != nil {
		return nil, err
	}
	st.Service = svc

	admin := &auth.Principal{Kind: "local", Session: "local-ceremony", ARN: "local:ceremony", Permissions: []string{"*"}}
	ctx := context.Background()
	for _, e := range Envs {
		csrResp, err := svc.CACSR(ctx, admin, e.Name, model.CACSRRequest{
			CommonName: "LOCAL TEST Intermediate " + e.Name, Organization: "Globex",
		})
		if err != nil {
			return nil, err
		}
		csr, err := pki.ParseCSR([]byte(csrResp.CSRPEM))
		if err != nil {
			return nil, err
		}
		rootKey, root, err := pkitest.NewRoot("LOCAL TEST Root " + e.Name)
		if err != nil {
			return nil, err
		}
		inter, err := pkitest.SignIntermediate(rootKey, root, csr, 5*365*24*time.Hour)
		if err != nil {
			return nil, err
		}
		if _, err := svc.CAInstall(ctx, admin, e.Name, model.CAInstallRequest{ChainPEM: string(pki.EncodeCertificates(inter, root))}); err != nil {
			return nil, err
		}
		st.Roots[e.Name] = root
	}
	return st, nil
}

// Handler serves the stack with the given authenticator (auth.Local for
// laptop use, an STSVerifier against a fake STS in tests).
func (s *Stack) Handler(authn auth.Authenticator, log *slog.Logger) http.Handler {
	return api.New(s.Service, authn, log)
}
