package kmssigner_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/AUTORQ/adl-signing-server/internal/kmssigner"
	"github.com/AUTORQ/adl-signing-server/internal/pki"
	"github.com/AUTORQ/adl-signing-server/internal/pki/pkitest"
)

// The interesting part is that certificates and CRLs signed through the KMS
// adapter verify, for both the RSA keys we run in production and ECDSA.
func TestSignerIssuesVerifiableCertificates(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, _ := pki.GenerateKey("ecdsa-p256")

	for name, key := range map[string]crypto.Signer{"rsa": rsaKey, "ecdsa": ecKey} {
		t.Run(name, func(t *testing.T) {
			fake := &kmssigner.Fake{Key: key, ID: "arn:aws:kms:us-east-1:111111111111:key/test"}
			signer, err := kmssigner.New(context.Background(), fake, "alias/test")
			if err != nil {
				t.Fatal(err)
			}
			if signer.KeyID() != fake.ID {
				t.Errorf("key id %q", signer.KeyID())
			}
			h, err := pkitest.NewHierarchy("KMS", signer)
			if err != nil {
				t.Fatal(err)
			}
			iss, err := pki.NewIssuer(signer, h.Chain(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			devKey, _ := pki.GenerateKey("rsa2048")
			if _, err := iss.IssueDevice("GLXADL001", devKey.Public(), pki.DeviceProfile{Validity: time.Hour}, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := pki.CreateCSR(signer, pkix.Name{CommonName: "intermediate"}); err != nil {
				t.Fatal(err)
			}
			if fake.Calls.Load() < 3 {
				t.Errorf("expected KMS to be used for signing, got %d calls", fake.Calls.Load())
			}
		})
	}
}
