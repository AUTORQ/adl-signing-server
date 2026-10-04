// Package pkitest builds throwaway CA hierarchies for tests and for the
// signer's local mode.
package pkitest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// Hierarchy is a root and one intermediate.
type Hierarchy struct {
	RootKey         crypto.Signer
	Root            *x509.Certificate
	IntermediateKey crypto.Signer
	Intermediate    *x509.Certificate
}

// Chain returns intermediate then root, the shape the server stores.
func (h *Hierarchy) Chain() []*x509.Certificate {
	return []*x509.Certificate{h.Intermediate, h.Root}
}

// NewRoot makes a self signed root with an ECDSA P-256 key.
func NewRoot(cn string) (crypto.Signer, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return key, cert, err
}

// SignIntermediate plays the role of the offline root: it signs csr as a
// pathlen:0 intermediate.
func SignIntermediate(rootKey crypto.Signer, root *x509.Certificate, csr *x509.CertificateRequest, validity time.Duration) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, csr.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// NewHierarchy makes a root and an intermediate whose key is interKey (or a
// fresh P-256 key when nil).
func NewHierarchy(name string, interKey crypto.Signer) (*Hierarchy, error) {
	rootKey, root, err := NewRoot(name + " Root")
	if err != nil {
		return nil, err
	}
	if interKey == nil {
		interKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: name + " Intermediate"},
	}, interKey)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	inter, err := SignIntermediate(rootKey, root, csr, 10*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	return &Hierarchy{RootKey: rootKey, Root: root, IntermediateKey: interKey, Intermediate: inter}, nil
}
