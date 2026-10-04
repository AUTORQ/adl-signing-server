// Package pki contains the certificate logic: CSR validation, the device
// certificate profile, CRLs and PEM helpers. It works with any crypto.Signer
// so the same code runs against KMS in AWS and plain keys in tests.
package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	pemCertificate = "CERTIFICATE"
	pemCSR         = "CERTIFICATE REQUEST"
	pemPrivateKey  = "PRIVATE KEY"
)

// DeviceProfile describes the leaf certificates we hand out. The defaults
// match what the legacy scripts produced so firmware and the cloud side do
// not notice the move.
type DeviceProfile struct {
	Organization string
	Validity     time.Duration
	// Backdate shifts NotBefore into the past to absorb clock skew on
	// whatever validates the certificate.
	Backdate time.Duration
}

// Issuer signs device certificates with an intermediate CA.
type Issuer struct {
	signer crypto.Signer
	cert   *x509.Certificate
	// chain holds the issuing certificate followed by its parents.
	chain []*x509.Certificate
}

// NewIssuer checks that cert belongs to signer, is a usable CA and chains to
// the last certificate in parents (normally the root).
func NewIssuer(signer crypto.Signer, chain []*x509.Certificate, now time.Time) (*Issuer, error) {
	if len(chain) == 0 {
		return nil, errors.New("issuer chain is empty")
	}
	cert := chain[0]
	if err := MatchesPublicKey(cert, signer.Public()); err != nil {
		return nil, err
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return nil, errors.New("issuer certificate is not a CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("issuer certificate is missing the certSign key usage")
	}
	if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("issuer certificate is not valid now (valid %s to %s)",
			cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	if err := VerifyChain(chain, now); err != nil {
		return nil, err
	}
	return &Issuer{signer: signer, cert: cert, chain: chain}, nil
}

// Certificate returns the issuing CA certificate.
func (i *Issuer) Certificate() *x509.Certificate { return i.cert }

// Chain returns the issuing CA certificate followed by its parents.
func (i *Issuer) Chain() []*x509.Certificate { return i.chain }

// ChainPEM is what devices get as their "-chain.pem": the issuing CA first,
// then everything above it.
func (i *Issuer) ChainPEM() []byte { return EncodeCertificates(i.chain...) }

// IssueDevice signs a client certificate for deviceID over pub.
func (i *Issuer) IssueDevice(deviceID string, pub crypto.PublicKey, p DeviceProfile, now time.Time) (*x509.Certificate, error) {
	if err := CheckPublicKey(pub); err != nil {
		return nil, err
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	ski, err := SubjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	notBefore := now.Add(-p.Backdate).UTC().Truncate(time.Second)
	notAfter := now.Add(p.Validity).UTC().Truncate(time.Second)
	// A leaf that outlives its issuer fails path validation on most stacks,
	// so clamp it rather than hand out something that breaks later.
	if notAfter.After(i.cert.NotAfter) {
		notAfter = i.cert.NotAfter
	}

	usage := x509.KeyUsageDigitalSignature
	if _, ok := pub.(*rsa.PublicKey); ok {
		usage |= x509.KeyUsageKeyEncipherment
	}

	subject := pkix.Name{CommonName: deviceID}
	if p.Organization != "" {
		subject.Organization = []string{p.Organization}
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              usage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski,
		SignatureAlgorithm:    SignatureAlgorithmFor(i.signer.Public()),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.cert, pub, i.signer)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse issued certificate: %w", err)
	}
	// Check what came back from the signer (KMS) actually verifies
	// before anyone flashes it.
	if err := cert.CheckSignatureFrom(i.cert); err != nil {
		return nil, fmt.Errorf("issued certificate does not verify against issuer: %w", err)
	}
	return cert, nil
}

// RevokedEntry is one line in a CRL.
type RevokedEntry struct {
	Serial    *big.Int
	RevokedAt time.Time
	Reason    int
}

// CreateCRL signs a CRL listing entries.
func (i *Issuer) CreateCRL(entries []RevokedEntry, number *big.Int, now time.Time, validity time.Duration) ([]byte, error) {
	list := make([]x509.RevocationListEntry, 0, len(entries))
	for _, e := range entries {
		list = append(list, x509.RevocationListEntry{
			SerialNumber:   e.Serial,
			RevocationTime: e.RevokedAt.UTC(),
			ReasonCode:     e.Reason,
		})
	}
	tmpl := &x509.RevocationList{
		Number:                    number,
		ThisUpdate:                now.UTC().Truncate(time.Second),
		NextUpdate:                now.Add(validity).UTC().Truncate(time.Second),
		RevokedCertificateEntries: list,
		SignatureAlgorithm:        SignatureAlgorithmFor(i.signer.Public()),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, i.cert, i.signer)
	if err != nil {
		return nil, fmt.Errorf("sign crl: %w", err)
	}
	return der, nil
}

// CreateCSR builds a PKCS#10 request signed by key.
func CreateCSR(key crypto.Signer, subject pkix.Name) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: SignatureAlgorithmFor(key.Public()),
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create csr: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemCSR, Bytes: der}), nil
}

// ParseCSR decodes a PEM CSR, checks its self signature and key strength.
func ParseCSR(data []byte) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != pemCSR {
		return nil, errors.New("csr is not a PEM \"CERTIFICATE REQUEST\" block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("csr has trailing data")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature is invalid: %w", err)
	}
	if err := CheckPublicKey(csr.PublicKey); err != nil {
		return nil, err
	}
	return csr, nil
}

// CheckPublicKey enforces the key types we are willing to certify.
// RSA 2048-4096 covers the ESP32-S3 DS peripheral; P-256/P-384 are allowed for
// parts that keep the key in encrypted flash instead.
func CheckPublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits < 2048 || bits > 4096 {
			return fmt.Errorf("rsa key size %d not allowed (2048-4096)", bits)
		}
		if k.E != 65537 {
			return fmt.Errorf("rsa public exponent %d not allowed", k.E)
		}
		return nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384():
			return nil
		}
		return fmt.Errorf("ecdsa curve %s not allowed", k.Curve.Params().Name)
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
}

// KeyAlgorithm returns a short human label like "RSA-2048" or "ECDSA-P256".
func KeyAlgorithm(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "ECDSA-P256"
		case elliptic.P384():
			return "ECDSA-P384"
		}
		return "ECDSA-" + k.Curve.Params().Name
	}
	return fmt.Sprintf("%T", pub)
}

// SignatureAlgorithmFor picks the signature algorithm for a CA key. The
// legacy intermediate used sha256WithRSA for leaves, so we keep that.
func SignatureAlgorithmFor(pub crypto.PublicKey) x509.SignatureAlgorithm {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P384() {
			return x509.ECDSAWithSHA384
		}
		return x509.ECDSAWithSHA256
	}
	return x509.UnknownSignatureAlgorithm
}

// GenerateKey creates a device key. alg is "rsa2048" (default) or "ecdsa-p256".
func GenerateKey(alg string) (crypto.Signer, error) {
	switch alg {
	case "", "rsa2048", "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "ecdsa-p256", "p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return nil, fmt.Errorf("unknown key algorithm %q (use rsa2048 or ecdsa-p256)", alg)
}

// NewSerial returns a random positive 127-bit serial number.
func NewSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("generate serial: %w", err)
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// SerialHex formats a serial the way openssl does, minus the colons.
func SerialHex(n *big.Int) string {
	return fmt.Sprintf("%X", n)
}

// ParseSerialHex is the inverse of SerialHex.
func ParseSerialHex(s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok || n.Sign() <= 0 {
		return nil, fmt.Errorf("invalid serial %q", s)
	}
	return n, nil
}

// Fingerprint is the hex SHA-256 of the DER certificate.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// PublicKeyFingerprint is the hex SHA-256 of the DER SubjectPublicKeyInfo.
func PublicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// SubjectKeyID computes the RFC 5280 method 1 key identifier.
func SubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki.PublicKey.Bytes)
	return sum[:], nil
}

type publicKeyEqualer interface {
	Equal(crypto.PublicKey) bool
}

// MatchesPublicKey errors unless cert carries pub.
func MatchesPublicKey(cert *x509.Certificate, pub crypto.PublicKey) error {
	eq, ok := cert.PublicKey.(publicKeyEqualer)
	if !ok || !eq.Equal(pub) {
		return errors.New("certificate public key does not match the signing key")
	}
	return nil
}

// VerifyChain checks that chain[0] chains through chain[1:] to a self signed
// root at the end of the slice.
func VerifyChain(chain []*x509.Certificate, now time.Time) error {
	if len(chain) < 2 {
		return errors.New("chain must contain the issuing certificate and at least its root")
	}
	root := chain[len(chain)-1]
	if err := root.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("last certificate in chain is not a self-signed root: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	for _, c := range chain[1 : len(chain)-1] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("chain does not verify: %w", err)
	}
	return nil
}

// EncodeCertificates PEM encodes certs in order.
func EncodeCertificates(certs ...*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: pemCertificate, Bytes: c.Raw})
	}
	return buf.Bytes()
}

// ParseCertificates decodes every CERTIFICATE block in data.
func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != pemCertificate {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM certificates found")
	}
	return out, nil
}

// EncodePrivateKey writes key as PKCS#8 PEM, which mbedTLS and the Espressif
// tooling both read.
func EncodePrivateKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPrivateKey, Bytes: der}), nil
}

// ParsePrivateKey reads PKCS#8, PKCS#1 or SEC1 PEM keys (the legacy openssl
// scripts may have produced any of them).
func ParsePrivateKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key is not PEM")
	}
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck // just detecting it
		return nil, errors.New("encrypted private keys are not supported")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key block %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
	return s, nil
}
