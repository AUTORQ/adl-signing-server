package service_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/edge-labs/adl-signing-server/internal/archive"
	"github.com/edge-labs/adl-signing-server/internal/auth"
	"github.com/edge-labs/adl-signing-server/internal/kmssigner"
	"github.com/edge-labs/adl-signing-server/internal/model"
	"github.com/edge-labs/adl-signing-server/internal/pki"
	"github.com/edge-labs/adl-signing-server/internal/pki/pkitest"
	"github.com/edge-labs/adl-signing-server/internal/service"
	"github.com/edge-labs/adl-signing-server/internal/store"
)

var (
	admin     = &auth.Principal{ARN: "arn:admin", Kind: "assumed-role", Role: "adl-admin", Session: "scott", Permissions: []string{"*"}}
	developer = &auth.Principal{ARN: "arn:dev", Kind: "assumed-role", Role: "dev", Session: "jane", Permissions: []string{"dev:issue", "dev:read", "dev:key-read"}}
	station   = &auth.Principal{ARN: "arn:station", Kind: "assumed-role", Role: "adl-factory-station", Session: "line-1", Permissions: []string{"prod:issue", "prod:read", "prod:provision"}}
	readonly  = &auth.Principal{ARN: "arn:ro", Kind: "assumed-role", Role: "ro", Session: "bob", Permissions: []string{"dev:read"}}
)

type harness struct {
	svc     *service.Service
	cas     *service.CAs
	store   *store.Memory
	archive *archive.Memory
	roots   map[string]*x509.Certificate
	rootKey map[string]crypto.Signer
}

func newHarness(t *testing.T, install bool) *harness {
	t.Helper()
	h := &harness{store: store.NewMemory(), archive: archive.NewMemory(), roots: map[string]*x509.Certificate{}, rootKey: map[string]crypto.Signer{}}
	keys := map[string]crypto.Signer{}
	for _, env := range []string{"dev", "prod"} {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		keys[env] = k
	}
	factory := func(ctx context.Context, env string) (crypto.Signer, error) {
		return kmssigner.New(ctx, &kmssigner.Fake{Key: keys[env], ID: "key-" + env}, "key-"+env)
	}
	cas := service.NewCAs(factory, h.archive, nil)
	h.cas = cas
	svc, err := service.New(service.Options{
		Store: h.store, Archive: h.archive, CAs: cas, Organization: "EDGE Labs",
		Envs: []service.EnvConfig{
			{Name: "dev", DevicePrefix: "DVTADL", Validity: 10 * 365 * 24 * time.Hour, AllowKeyEscrow: true},
			{Name: "prod", DevicePrefix: "DVTADL", Validity: 10 * 365 * 24 * time.Hour, RequireChipID: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	if install {
		for _, env := range []string{"dev", "prod"} {
			h.ceremony(t, env)
		}
	}
	return h
}

// ceremony does what the CA admin does by hand: get a CSR for the KMS key,
// have the offline root sign it, install the result.
func (h *harness) ceremony(t *testing.T, env string) {
	t.Helper()
	ctx := context.Background()
	csrResp, err := h.svc.CACSR(ctx, admin, env, model.CACSRRequest{CommonName: "EDGE Labs Intermediate CA " + env, Organization: "EDGE Labs"})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseCSR([]byte(csrResp.CSRPEM))
	if err != nil {
		t.Fatal(err)
	}
	rootKey, root, err := pkitest.NewRoot("AutorQ Root CA " + env)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := pkitest.SignIntermediate(rootKey, root, csr, 20*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st, err := h.svc.CAInstall(ctx, admin, env, model.CAInstallRequest{ChainPEM: string(pki.EncodeCertificates(inter, root))})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Configured {
		t.Fatal("ca should be configured")
	}
	h.roots[env] = root
	h.rootKey[env] = rootKey
}

func csrFor(t *testing.T, cn string) (crypto.Signer, string) {
	t.Helper()
	key, err := pki.GenerateKey("rsa2048")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.CreateCSR(key, pkix.Name{CommonName: cn})
	if err != nil {
		t.Fatal(err)
	}
	return key, string(csr)
}

func keyPEM(t *testing.T, k crypto.Signer) string {
	b, err := pki.EncodePrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func errCode(err error) string {
	var se *service.Error
	if errors.As(err, &se) {
		return se.Code
	}
	if err == nil {
		return ""
	}
	return "other:" + err.Error()
}

func (h *harness) verify(t *testing.T, env string, resp *model.IssueResponse) *x509.Certificate {
	t.Helper()
	leaf, err := pki.ParseCertificates([]byte(resp.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := pki.ParseCertificates([]byte(resp.ChainPEM))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(h.roots[env])
	inter := x509.NewCertPool()
	for _, c := range chain {
		inter.AddCert(c)
	}
	if _, err := leaf[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("issued cert does not chain to %s root: %v", env, err)
	}
	return leaf[0]
}

func TestIssueBeforeCeremony(t *testing.T) {
	h := newHarness(t, false)
	_, csr := csrFor(t, "x")
	_, err := h.svc.Issue(context.Background(), developer, model.IssueRequest{Env: "dev", CSR: csr})
	if errCode(err) != "ca_not_configured" {
		t.Fatalf("got %v", err)
	}
	st, err := h.svc.CAStatus(context.Background(), "dev")
	if err != nil || st.Configured || st.KeyAlgorithm != "RSA-2048" {
		t.Fatalf("status %+v %v", st, err)
	}
	if _, err := h.svc.CACSR(context.Background(), developer, "dev", model.CACSRRequest{CommonName: "x"}); errCode(err) != "forbidden" {
		t.Errorf("developer got a CA CSR: %v", err)
	}
}

func TestDeveloperMintAndRecover(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	key, csr := csrFor(t, "")
	resp, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: csr, PrivateKey: keyPEM(t, key), Labels: map[string]string{"board": "rev-c"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Device.ID != "DVTADL001" || resp.Device.Owner != "dev/jane" || resp.Device.Status != model.DeviceIssued {
		t.Errorf("unexpected device %+v", resp.Device)
	}
	leaf := h.verify(t, "dev", resp)
	if leaf.Subject.CommonName != "DVTADL001" || leaf.Subject.Organization[0] != "EDGE Labs" {
		t.Errorf("subject %s", leaf.Subject)
	}
	escrowKey := archive.EscrowKey("dev", "DVTADL001", resp.Certificate.Serial)
	if !h.archive.SensitiveKeys[escrowKey] {
		t.Error("escrowed key was not written as sensitive")
	}

	// A week later the developer has lost everything.
	b, err := h.svc.Bundle(ctx, developer, "DVTADL001", "", true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pki.ParsePrivateKey([]byte(b.PrivateKeyPEM))
	if err != nil || !got.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()) {
		t.Fatal("recovered key does not match")
	}
	if b.CertificatePEM != resp.CertificatePEM || b.ChainPEM != resp.ChainPEM {
		t.Error("bundle does not match issued material")
	}

	// Read-only folks can see the cert but not the key.
	if _, err := h.svc.Bundle(ctx, readonly, "DVTADL001", "", false); err != nil {
		t.Errorf("readonly bundle: %v", err)
	}
	if _, err := h.svc.Bundle(ctx, readonly, "DVTADL001", "", true); errCode(err) != "forbidden" {
		t.Errorf("readonly got key: %v", err)
	}

	evs, _ := h.svc.Audit(ctx, admin, time.Now())
	var actions []string
	for _, e := range evs.Events {
		actions = append(actions, e.Action)
	}
	if !strings.Contains(strings.Join(actions, ","), "certificate.issue") || !strings.Contains(strings.Join(actions, ","), "key.retrieve") {
		t.Errorf("audit trail missing events: %v", actions)
	}
}

func TestPermissionsAndEscrowPolicy(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	key, csr := csrFor(t, "")
	if _, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "prod", CSR: csr}); errCode(err) != "forbidden" {
		t.Errorf("developer issued prod: %v", err)
	}
	if _, err := h.svc.Issue(ctx, station, model.IssueRequest{Env: "prod", CSR: csr}); errCode(err) != "bad_request" {
		t.Errorf("prod issued without a chip id: %v", err)
	}
	if _, err := h.svc.Issue(ctx, station, model.IssueRequest{Env: "prod", CSR: csr, ChipID: "f412fa000001", PrivateKey: keyPEM(t, key)}); errCode(err) != "bad_request" {
		t.Errorf("prod accepted an escrowed key: %v", err)
	}
	other, _ := csrFor(t, "")
	if _, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: csr, PrivateKey: keyPEM(t, other)}); errCode(err) != "bad_request" {
		t.Errorf("mismatched escrow key accepted: %v", err)
	}
	if _, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: "garbage"}); errCode(err) != "bad_request" {
		t.Errorf("garbage csr: %v", err)
	}
	if _, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: csr, DeviceID: "bad id!"}); errCode(err) != "bad_request" {
		t.Errorf("bad device id: %v", err)
	}
}

func TestExplicitIDBumpsSequenceAndReplace(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, csr := csrFor(t, "")
	if _, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: csr, DeviceID: "DVTADL050"}); errCode(err) != "bad_request" {
		t.Errorf("developer pinned a managed id: %v", err)
	}
	// Ids outside the managed range are fine (bench jigs and the like).
	if _, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: csr, DeviceID: "BENCH-JIG-01"}); err != nil {
		t.Errorf("custom id: %v", err)
	}
	first, err := h.svc.Issue(ctx, admin, model.IssueRequest{Env: "dev", CSR: csr, DeviceID: "DVTADL050"})
	if err != nil {
		t.Fatal(err)
	}
	_, csr2 := csrFor(t, "")
	next, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: csr2})
	if err != nil {
		t.Fatal(err)
	}
	if next.Device.ID != "DVTADL051" {
		t.Errorf("allocator should skip past 050, got %s", next.Device.ID)
	}

	if _, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: csr2, DeviceID: "DVTADL050"}); errCode(err) != "device_exists" {
		t.Errorf("re-issue without replace: %v", err)
	}
	again, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: csr2, DeviceID: "DVTADL050", Replace: true})
	if err != nil {
		t.Fatal(err)
	}
	old, _ := h.store.GetCertificate(ctx, first.Certificate.Serial)
	if old.Status != model.CertRevoked || old.RevocationReason != "superseded" {
		t.Errorf("old cert should be superseded, got %+v", old)
	}
	if again.Device.CurrentSerial == first.Certificate.Serial {
		t.Error("current serial not updated")
	}
	crl := h.crl(t, "dev")
	if len(crl.RevokedCertificateEntries) != 1 || pki.SerialHex(crl.RevokedCertificateEntries[0].SerialNumber) != first.Certificate.Serial {
		t.Errorf("crl should list the superseded cert: %+v", crl.RevokedCertificateEntries)
	}
}

func (h *harness) crl(t *testing.T, env string) *x509.RevocationList {
	t.Helper()
	der, err := h.svc.CRL(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := h.svc.CAStatus(context.Background(), env)
	chain, _ := pki.ParseCertificates([]byte(st.ChainPEM))
	if err := crl.CheckSignatureFrom(chain[0]); err != nil {
		t.Fatalf("crl signature: %v", err)
	}
	return crl
}

func TestEndOfLineFlow(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, csr := csrFor(t, "")
	resp, err := h.svc.Issue(ctx, station, model.IssueRequest{Env: "prod", CSR: csr, ChipID: "F4:12:FA:00:11:22"})
	if err != nil {
		t.Fatal(err)
	}
	h.verify(t, "prod", resp)
	if resp.Device.ChipID != "f412fa001122" {
		t.Errorf("chip id not normalised: %q", resp.Device.ChipID)
	}

	// Same chip on the line again must not get a second identity.
	_, csr2 := csrFor(t, "")
	_, err = h.svc.Issue(ctx, station, model.IssueRequest{Env: "prod", CSR: csr2, ChipID: "f412fa001122"})
	var se *service.Error
	if !errors.As(err, &se) || se.Code != "chip_already_assigned" || se.Details["device_id"] != resp.Device.ID {
		t.Fatalf("expected chip_already_assigned for %s, got %v", resp.Device.ID, err)
	}

	id := resp.Device.ID
	if _, err := h.svc.MarkProvisioned(ctx, station, id, model.ProvisionRequest{Serial: "DEADBEEF", ChipID: "f412fa001122", Station: "line-1"}); errCode(err) != "serial_mismatch" {
		t.Errorf("wrong serial: %v", err)
	}
	if _, err := h.svc.MarkProvisioned(ctx, station, id, model.ProvisionRequest{Serial: resp.Certificate.Serial, ChipID: "aaaaaaaaaaaa", Station: "line-1"}); errCode(err) != "chip_mismatch" {
		t.Errorf("wrong chip: %v", err)
	}
	dev, err := h.svc.MarkProvisioned(ctx, station, id, model.ProvisionRequest{Serial: resp.Certificate.Serial, ChipID: "f412fa001122", Station: "line-1", FirmwareVersion: "1.4.2"})
	if err != nil {
		t.Fatal(err)
	}
	if dev.Status != model.DeviceProvisioned || dev.ProvisionedBy != "adl-factory-station/line-1" || dev.FirmwareVersion != "1.4.2" {
		t.Errorf("unexpected device after provisioning: %+v", dev)
	}
	// Retrying the confirmation is harmless.
	if _, err := h.svc.MarkProvisioned(ctx, station, id, model.ProvisionRequest{Serial: resp.Certificate.Serial, ChipID: "f412fa001122", Station: "line-1"}); err != nil {
		t.Errorf("idempotent provision: %v", err)
	}

	// A station cannot quietly re-key a shipped device.
	if _, err := h.svc.Issue(ctx, station, model.IssueRequest{Env: "prod", CSR: csr2, DeviceID: id, Replace: true}); errCode(err) != "forbidden" {
		t.Errorf("station replaced provisioned device: %v", err)
	}
	// Developers cannot even see prod.
	if _, err := h.svc.GetDevice(ctx, developer, id); errCode(err) != "forbidden" {
		t.Errorf("developer read prod device: %v", err)
	}
	if _, err := h.svc.Bundle(ctx, station, id, "", true); errCode(err) != "forbidden" {
		t.Errorf("station asked for a key: %v", err)
	}
}

func TestRevoke(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, csr := csrFor(t, "")
	resp, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: csr})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Revoke(ctx, developer, resp.Device.ID, model.RevokeRequest{Reason: "keyCompromise"}); errCode(err) != "forbidden" {
		t.Errorf("developer revoked: %v", err)
	}
	if _, err := h.svc.Revoke(ctx, admin, resp.Device.ID, model.RevokeRequest{Reason: "made-up"}); errCode(err) != "bad_request" {
		t.Errorf("bad reason: %v", err)
	}
	detail, err := h.svc.Revoke(ctx, admin, resp.Device.ID, model.RevokeRequest{Reason: "keyCompromise"})
	if err != nil {
		t.Fatal(err)
	}
	if detail.Device.Status != model.DeviceRevoked || detail.Certificates[0].RevocationReason != "keyCompromise" {
		t.Errorf("unexpected detail %+v", detail)
	}
	crl := h.crl(t, "dev")
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Errorf("crl entries %+v", crl.RevokedCertificateEntries)
	}
	if prod := h.crl(t, "prod"); len(prod.RevokedCertificateEntries) != 0 {
		t.Error("dev revocation leaked into prod crl")
	}
	if _, err := h.svc.Revoke(ctx, admin, resp.Device.ID, model.RevokeRequest{}); errCode(err) != "not_found" {
		t.Errorf("double revoke: %v", err)
	}
}

func TestImportLegacy(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()

	// Stand-in for the droplet's "EDGE Labs Intermediate CA".
	legacy, err := pkitest.NewHierarchy("Legacy", nil)
	if err != nil {
		t.Fatal(err)
	}
	legacyIss, _ := pki.NewIssuer(legacy.IntermediateKey, legacy.Chain(), time.Now())
	key, _ := pki.GenerateKey("rsa2048")
	cert, err := legacyIss.IssueDevice("DVTADL016", key.Public(), pki.DeviceProfile{Organization: "EDGE Labs", Validity: time.Hour * 24 * 3650}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req := model.ImportRequest{
		Env: "dev", CertificatePEM: string(pki.EncodeCertificates(cert)),
		ChainPEM: string(legacyIss.ChainPEM()), PrivateKeyPEM: keyPEM(t, key),
	}
	if _, err := h.svc.Import(ctx, developer, req); errCode(err) != "forbidden" {
		t.Errorf("developer imported: %v", err)
	}
	detail, err := h.svc.Import(ctx, admin, req)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Device.ID != "DVTADL016" || !detail.Certificates[0].Imported || !detail.Certificates[0].KeyEscrowed {
		t.Errorf("unexpected import result %+v", detail)
	}
	if _, err := h.svc.Import(ctx, admin, req); errCode(err) != "already_imported" {
		t.Errorf("second import: %v", err)
	}
	b, err := h.svc.Bundle(ctx, developer, "DVTADL016", "", true)
	if err != nil || b.PrivateKeyPEM == "" {
		t.Fatalf("legacy key not recoverable: %v", err)
	}

	// Counter moved past the imported number.
	_, csr := csrFor(t, "")
	resp, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: csr})
	if err != nil || resp.Device.ID != "DVTADL017" {
		t.Fatalf("next id after import: %+v %v", resp, err)
	}

	// Prod keys are never escrowed, even on import.
	req.Env = "prod"
	if _, err := h.svc.Import(ctx, admin, req); errCode(err) != "bad_request" {
		t.Errorf("prod key import: %v", err)
	}

	// Revoking a legacy cert must not put it on our CA's CRL (it is not
	// ours to list).
	if _, err := h.svc.Revoke(ctx, admin, "DVTADL016", model.RevokeRequest{Reason: "superseded"}); err != nil {
		t.Fatal(err)
	}
	for _, e := range h.crl(t, "dev").RevokedCertificateEntries {
		if e.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			t.Error("legacy serial on new CA's crl")
		}
	}
}

func TestListDevicesScopedToPermissions(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, a := csrFor(t, "")
	_, b := csrFor(t, "")
	if _, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: a}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Issue(ctx, station, model.IssueRequest{Env: "prod", CSR: b, ChipID: "f412fa000002"}); err != nil {
		t.Fatal(err)
	}
	list, err := h.svc.ListDevices(ctx, developer, "")
	if err != nil || len(list.Devices) != 1 || list.Devices[0].Env != "dev" {
		t.Errorf("developer list: %+v %v", list, err)
	}
	all, err := h.svc.ListDevices(ctx, admin, "")
	if err != nil || len(all.Devices) != 2 {
		t.Errorf("admin list: %+v %v", all, err)
	}
}

func TestCAInstallRejectsWrongKey(t *testing.T) {
	h := newHarness(t, false)
	// An intermediate signed for some other key must be refused.
	other, err := pkitest.NewHierarchy("Other", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.CAInstall(context.Background(), admin, "dev", model.CAInstallRequest{ChainPEM: string(pki.EncodeCertificates(other.Chain()...))})
	if errCode(err) != "bad_request" {
		t.Fatalf("got %v", err)
	}
}

// staleRevoked hides revocations from ListRevoked, like a DynamoDB GSI that
// hasn't caught up yet.
type staleRevoked struct{ *store.Memory }

func (staleRevoked) ListRevoked(context.Context, string) ([]*model.Certificate, error) {
	return nil, nil
}

func TestCRLIncludesJustRevokedEvenWithStaleIndex(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, csr := csrFor(t, "")
	resp, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: csr})
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild the service over a store whose revoked index lags.
	svc, err := service.New(service.Options{
		Store: staleRevoked{h.store}, Archive: h.archive, CAs: h.cas, Organization: "EDGE Labs",
		Envs: []service.EnvConfig{{Name: "dev", DevicePrefix: "DVTADL", Validity: time.Hour, AllowKeyEscrow: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Revoke(ctx, admin, resp.Device.ID, model.RevokeRequest{Reason: "keyCompromise"}); err != nil {
		t.Fatal(err)
	}
	der, err := svc.CRL(ctx, "dev")
	if err != nil {
		t.Fatal(err)
	}
	crl, _ := x509.ParseRevocationList(der)
	if len(crl.RevokedCertificateEntries) != 1 || pki.SerialHex(crl.RevokedCertificateEntries[0].SerialNumber) != resp.Certificate.Serial {
		t.Fatalf("fresh revocation missing from CRL: %+v", crl.RevokedCertificateEntries)
	}
}

func TestDevCannotSquatOnProdChip(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, a := csrFor(t, "")
	_, b := csrFor(t, "")
	if _, err := h.svc.Issue(ctx, developer, model.IssueRequest{Env: "dev", CSR: a, ChipID: "f412fa00aaaa"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Issue(ctx, station, model.IssueRequest{Env: "prod", CSR: b, ChipID: "f412fa00aaaa"}); err != nil {
		t.Fatalf("a dev claim blocked prod provisioning: %v", err)
	}
}

func TestImportRetryAfterFailedDeviceWrite(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	legacy, _ := pkitest.NewHierarchy("Legacy", nil)
	iss, _ := pki.NewIssuer(legacy.IntermediateKey, legacy.Chain(), time.Now())
	key, _ := pki.GenerateKey("rsa2048")
	cert, _ := iss.IssueDevice("DVTADL009", key.Public(), pki.DeviceProfile{Validity: time.Hour}, time.Now())

	// Chip already belongs to another prod device, so the first attempt fails.
	_, csr := csrFor(t, "")
	if _, err := h.svc.Issue(ctx, station, model.IssueRequest{Env: "prod", CSR: csr, ChipID: "f412fa00bbbb"}); err != nil {
		t.Fatal(err)
	}
	req := model.ImportRequest{Env: "prod", CertificatePEM: string(pki.EncodeCertificates(cert)), ChipID: "f412fa00bbbb"}
	if _, err := h.svc.Import(ctx, admin, req); errCode(err) != "chip_already_assigned" {
		t.Fatalf("expected chip conflict, got %v", err)
	}
	req.ChipID = ""
	if _, err := h.svc.Import(ctx, admin, req); err != nil {
		t.Fatalf("retry stuck after failed import: %v", err)
	}
}
