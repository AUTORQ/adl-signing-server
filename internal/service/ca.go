package service

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/edge-labs/adl-signing-server/internal/archive"
	"github.com/edge-labs/adl-signing-server/internal/pki"
)

// ErrCANotConfigured means the KMS key exists but nobody has installed the
// signed intermediate certificate for it yet.
var ErrCANotConfigured = errors.New("ca certificate not installed")

// SignerFactory returns the signing key for an environment's issuing CA.
type SignerFactory func(ctx context.Context, env string) (crypto.Signer, error)

// CAs hands out issuers per environment. The private key comes from
// SignerFactory (KMS); the certificate chain lives in the archive bucket so
// it can be rotated without a redeploy.
type CAs struct {
	newSigner SignerFactory
	archive   archive.Store
	ttl       time.Duration
	now       func() time.Time

	mu      sync.Mutex
	signers map[string]crypto.Signer
	issuers map[string]cachedIssuer
}

type cachedIssuer struct {
	issuer  *pki.Issuer
	fetched time.Time
}

func NewCAs(f SignerFactory, a archive.Store, now func() time.Time) *CAs {
	if now == nil {
		now = time.Now
	}
	return &CAs{
		newSigner: f, archive: a, ttl: 5 * time.Minute, now: now,
		signers: map[string]crypto.Signer{}, issuers: map[string]cachedIssuer{},
	}
}

// Signer returns (and caches) the env's signer.
func (c *CAs) Signer(ctx context.Context, env string) (crypto.Signer, error) {
	c.mu.Lock()
	s, ok := c.signers[env]
	c.mu.Unlock()
	if ok {
		return s, nil
	}
	s, err := c.newSigner(ctx, env)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.signers[env] = s
	c.mu.Unlock()
	return s, nil
}

// Issuer returns the current issuer for env, reloading the chain from the
// archive every few minutes so a rotation on one instance reaches the rest.
func (c *CAs) Issuer(ctx context.Context, env string) (*pki.Issuer, error) {
	now := c.now()
	c.mu.Lock()
	ci, ok := c.issuers[env]
	c.mu.Unlock()
	if ok && now.Sub(ci.fetched) < c.ttl {
		return ci.issuer, nil
	}
	signer, err := c.Signer(ctx, env)
	if err != nil {
		return nil, err
	}
	data, err := c.archive.Get(ctx, archive.CAChainKey(env))
	if errors.Is(err, archive.ErrNotFound) {
		return nil, ErrCANotConfigured
	}
	if err != nil {
		return nil, err
	}
	chain, err := pki.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("stored ca chain for %s: %w", env, err)
	}
	iss, err := pki.NewIssuer(signer, chain, now)
	if err != nil {
		return nil, fmt.Errorf("stored ca chain for %s: %w", env, err)
	}
	c.mu.Lock()
	c.issuers[env] = cachedIssuer{issuer: iss, fetched: now}
	c.mu.Unlock()
	return iss, nil
}

// Install validates and stores a new chain for env. The previous chain stays
// in the bucket's version history.
func (c *CAs) Install(ctx context.Context, env string, chain []*x509.Certificate) (*pki.Issuer, error) {
	signer, err := c.Signer(ctx, env)
	if err != nil {
		return nil, err
	}
	iss, err := pki.NewIssuer(signer, chain, c.now())
	if err != nil {
		return nil, err
	}
	pemChain := pki.EncodeCertificates(chain...)
	hist := fmt.Sprintf("ca/%s/history/%s.pem", env, pki.Fingerprint(chain[0]))
	if err := c.archive.Put(ctx, hist, pemChain, archive.PutOptions{ContentType: "application/x-pem-file"}); err != nil {
		return nil, err
	}
	if err := c.archive.Put(ctx, archive.CAChainKey(env), pemChain, archive.PutOptions{ContentType: "application/x-pem-file"}); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.issuers[env] = cachedIssuer{issuer: iss, fetched: c.now()}
	c.mu.Unlock()
	return iss, nil
}
