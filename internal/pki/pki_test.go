package pki_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/edge-labs/adl-signing-server/internal/pki"
	"github.com/edge-labs/adl-signing-server/internal/pki/pkitest"
)

func newIssuer(t *testing.T) (*pki.Issuer, *pkitest.Hierarchy) {
	t.Helper()
	h, err := pkitest.NewHierarchy("Test", nil)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := pki.NewIssuer(h.IntermediateKey, h.Chain(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return iss, h
}

func TestIssueDeviceMatchesLegacyProfile(t *testing.T) {
	iss, h := newIssuer(t)
	key, err := pki.GenerateKey("rsa2048")
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := pki.CreateCSR(key, pkix.Name{CommonName: "DVTADL099"})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, err := iss.IssueDevice("DVTADL099", csr.PublicKey, pki.DeviceProfile{
		Organization: "EDGE Labs",
		Validity:     10 * 365 * 24 * time.Hour,
		Backdate:     5 * time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	if cert.Subject.CommonName != "DVTADL099" || cert.Subject.Organization[0] != "EDGE Labs" {
		t.Errorf("unexpected subject %s", cert.Subject)
	}
	if cert.IsCA {
		t.Error("leaf must not be a CA")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Errorf("unexpected key usage %v", cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("unexpected ext key usage %v", cert.ExtKeyUsage)
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Error("expected RSA key in cert")
	}

	roots := x509.NewCertPool()
	roots.AddCert(h.Root)
	inter := x509.NewCertPool()
	inter.AddCert(h.Intermediate)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("issued cert does not verify: %v", err)
	}
}

func TestIssueClampsToIssuerExpiry(t *testing.T) {
	iss, h := newIssuer(t)
	key, _ := pki.GenerateKey("ecdsa-p256")
	cert, err := iss.IssueDevice("X1", key.Public(), pki.DeviceProfile{Validity: 50 * 365 * 24 * time.Hour}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotAfter.Equal(h.Intermediate.NotAfter) {
		t.Errorf("NotAfter %v should be clamped to %v", cert.NotAfter, h.Intermediate.NotAfter)
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Error("ECDSA leaf should not have keyEncipherment")
	}
}

func TestNewIssuerRejectsMismatchedKey(t *testing.T) {
	h, err := pkitest.NewHierarchy("Test", nil)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := pki.GenerateKey("ecdsa-p256")
	if _, err := pki.NewIssuer(other, h.Chain(), time.Now()); err == nil {
		t.Fatal("expected mismatch error")
	}
	// Chain without the root is not accepted either.
	if _, err := pki.NewIssuer(h.IntermediateKey, h.Chain()[:1], time.Now()); err == nil {
		t.Fatal("expected chain error")
	}
}

func TestCheckPublicKey(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Skip("cannot make small rsa key:", err)
	}
	if err := pki.CheckPublicKey(&small.PublicKey); err == nil {
		t.Error("1024-bit RSA should be rejected")
	}
}

func TestParseCSRRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "hello", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"} {
		if _, err := pki.ParseCSR([]byte(in)); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestCRL(t *testing.T) {
	iss, _ := newIssuer(t)
	now := time.Now()
	der, err := iss.CreateCRL([]pki.RevokedEntry{{Serial: big.NewInt(42), RevokedAt: now, Reason: 1}}, big.NewInt(7), now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(iss.Certificate()); err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Errorf("unexpected entries %+v", crl.RevokedCertificateEntries)
	}
}

func TestKeyRoundTrip(t *testing.T) {
	for _, alg := range []string{"rsa2048", "ecdsa-p256"} {
		key, err := pki.GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes, err := pki.EncodePrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		back, err := pki.ParsePrivateKey(pemBytes)
		if err != nil {
			t.Fatal(err)
		}
		if !back.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()) {
			t.Errorf("%s: key changed on round trip", alg)
		}
	}
}

func TestSerialHexRoundTrip(t *testing.T) {
	s, _ := pki.NewSerial()
	back, err := pki.ParseSerialHex(pki.SerialHex(s))
	if err != nil || back.Cmp(s) != 0 {
		t.Fatalf("round trip failed: %v", err)
	}
}
