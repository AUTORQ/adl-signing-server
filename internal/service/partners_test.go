package service_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/edge-labs/adl-signing-server/internal/archive"
	"github.com/edge-labs/adl-signing-server/internal/auth"
	"github.com/edge-labs/adl-signing-server/internal/kmssigner"
	"github.com/edge-labs/adl-signing-server/internal/model"
	"github.com/edge-labs/adl-signing-server/internal/pki"
	"github.com/edge-labs/adl-signing-server/internal/service"
	"github.com/edge-labs/adl-signing-server/internal/store"
)

// One deployment, two manufacturing partners, each with a dev and a prod
// intermediate. Device ids are the partner's prefix + the board's MAC.
var partnerEnvs = []service.EnvConfig{
	{Name: "edge-labs-dev", Partner: "edge-labs", Stage: "dev", Organization: "EDGE Labs", DevicePrefix: "DVTADL", DeviceIDFromChip: true, Validity: 365 * 24 * time.Hour, AllowKeyEscrow: true},
	{Name: "edge-labs-prod", Partner: "edge-labs", Stage: "prod", Organization: "EDGE Labs", DevicePrefix: "DVTADL", DeviceIDFromChip: true, Validity: 365 * 24 * time.Hour, RequireChipID: true},
	{Name: "acme-dev", Partner: "acme", Stage: "dev", Organization: "ACME", DevicePrefix: "BBB", DeviceIDFromChip: true, Validity: 365 * 24 * time.Hour},
	{Name: "acme-prod", Partner: "acme", Stage: "prod", Organization: "ACME", DevicePrefix: "BBB", DeviceIDFromChip: true, Validity: 365 * 24 * time.Hour, RequireChipID: true},
}

func partnerPerms(partner string) []string {
	var out []string
	for _, stage := range []string{"dev", "prod"} {
		for _, a := range []string{"issue", "read", "provision", "revoke"} {
			out = append(out, partner+"-"+stage+":"+a)
		}
	}
	return out
}

var (
	john = &auth.Principal{ARN: "arn:aws:iam::222222222222:user/john", Account: "222222222222", Kind: "user", User: "john", Permissions: partnerPerms("edge-labs")}
	tony = &auth.Principal{ARN: "arn:aws:iam::333333333333:user/tony", Account: "333333333333", Kind: "user", User: "tony", Permissions: partnerPerms("acme")}
)

func newPartnerHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{store: store.NewMemory(), archive: archive.NewMemory(), roots: map[string]*x509.Certificate{}, rootKey: map[string]crypto.Signer{}}
	keys := map[string]crypto.Signer{}
	for _, e := range partnerEnvs {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		keys[e.Name] = k
	}
	factory := func(ctx context.Context, env string) (crypto.Signer, error) {
		return kmssigner.New(ctx, &kmssigner.Fake{Key: keys[env], ID: "key-" + env}, "key-"+env)
	}
	h.cas = service.NewCAs(factory, h.archive, nil)
	svc, err := service.New(service.Options{Store: h.store, Archive: h.archive, CAs: h.cas, Organization: "unused", Envs: partnerEnvs})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	for _, e := range partnerEnvs {
		h.ceremony(t, e.Name)
	}
	return h
}

func (h *harness) issueChip(t *testing.T, p *auth.Principal, env, mac string, mod func(*model.IssueRequest)) (*model.IssueResponse, error) {
	t.Helper()
	_, csr := csrFor(t, "")
	req := model.IssueRequest{Env: env, CSR: csr, ChipID: mac}
	if mod != nil {
		mod(&req)
	}
	return h.svc.Issue(context.Background(), p, req)
}

func TestPartnersOnlyReachTheirOwnEnvironments(t *testing.T) {
	h := newPartnerHarness(t)
	ctx := context.Background()

	resp, err := h.issueChip(t, john, "edge-labs-dev", "3c:71:bf:4a:12:e0", nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf := h.verify(t, "edge-labs-dev", resp)
	if leaf.Subject.CommonName != "DVTADL3C71BF4A12E0" || !slices.Equal(leaf.Subject.Organization, []string{"EDGE Labs"}) {
		t.Errorf("subject %s", leaf.Subject)
	}

	if _, err := h.issueChip(t, john, "acme-dev", "3c:71:bf:4a:12:e1", nil); errCode(err) != "forbidden" {
		t.Errorf("john signing with ACME's intermediate: %v", err)
	}
	if _, err := h.svc.GetDevice(ctx, tony, "DVTADL3C71BF4A12E0"); errCode(err) != "forbidden" {
		t.Errorf("tony reading an EDGE Labs device: %v", err)
	}
	if _, err := h.svc.Revoke(ctx, tony, "DVTADL3C71BF4A12E0", model.RevokeRequest{Reason: "keyCompromise"}); errCode(err) != "forbidden" {
		t.Errorf("tony revoking an EDGE Labs device: %v", err)
	}
	l, err := h.svc.ListDevices(ctx, tony, "")
	if err != nil || len(l.Devices) != 0 {
		t.Errorf("tony sees %v, %v", l, err)
	}
	if _, err := h.svc.CACSR(ctx, john, "edge-labs-dev", model.CACSRRequest{CommonName: "x"}); errCode(err) != "forbidden" {
		t.Errorf("partners must not touch their intermediate: %v", err)
	}

	resp, err = h.issueChip(t, tony, "acme-prod", "001122334455", nil)
	if err != nil {
		t.Fatal(err)
	}
	if leaf := h.verify(t, "acme-prod", resp); leaf.Subject.CommonName != "BBB001122334455" || leaf.Subject.Organization[0] != "ACME" {
		t.Errorf("subject %s", leaf.Subject)
	}

	var names []string
	for _, e := range h.svc.Access(john) {
		names = append(names, e.Name+"/"+e.Partner+"/"+e.Stage)
	}
	if strings.Join(names, " ") != "edge-labs-dev/edge-labs/dev edge-labs-prod/edge-labs/prod" {
		t.Errorf("john's access: %v", names)
	}
	if got := len(h.svc.Access(admin)); got != 4 {
		t.Errorf("AutorQ staff reach %d environments, want all 4", got)
	}
}

func TestAutorQStaffActForAnyPartner(t *testing.T) {
	h := newPartnerHarness(t)
	for _, env := range []string{"edge-labs-dev", "acme-prod"} {
		resp, err := h.issueChip(t, admin, env, "0a0b0c0d0e0f", nil)
		if err != nil {
			t.Fatalf("%s: %v", env, err)
		}
		h.verify(t, env, resp)
	}
}

func TestDeviceIDComesFromTheMAC(t *testing.T) {
	h := newPartnerHarness(t)
	if _, err := h.issueChip(t, john, "edge-labs-dev", "", nil); errCode(err) != "bad_request" {
		t.Errorf("no MAC: %v", err)
	}
	if _, err := h.issueChip(t, john, "edge-labs-dev", "", func(r *model.IssueRequest) { r.DeviceID = "DVTADL017" }); errCode(err) != "bad_request" {
		t.Errorf("picking an id without a MAC: %v", err)
	}
	if _, err := h.issueChip(t, john, "edge-labs-dev", "3c71bf4a12e0", func(r *model.IssueRequest) { r.DeviceID = "DVTADL999" }); errCode(err) != "bad_request" {
		t.Errorf("id that is not prefix+MAC: %v", err)
	}
	if _, err := h.issueChip(t, john, "edge-labs-dev", "3c71bf4a12e0aabb", nil); errCode(err) != "bad_request" {
		t.Errorf("chip id that is not a MAC: %v", err)
	}
	if _, err := h.issueChip(t, john, "edge-labs-dev", "3C-71-BF-4A-12-E0", nil); err != nil {
		t.Fatal(err)
	}
	// The same board again: what EoL stations expect, so they can offer
	// to re-issue.
	_, err := h.issueChip(t, john, "edge-labs-dev", "3c71bf4a12e0", nil)
	if errCode(err) != "chip_already_assigned" {
		t.Fatalf("second issue: %v", err)
	}
	resp, err := h.issueChip(t, john, "edge-labs-dev", "3c71bf4a12e0", func(r *model.IssueRequest) { r.Replace = true })
	if err != nil || resp.Device.ID != "DVTADL3C71BF4A12E0" {
		t.Fatalf("replace: %v", err)
	}
}

// Within one deployment a device id lives in one environment. (AutorQ runs
// a signer per stage, so dev and prod never meet in one registry.)
func TestDeviceStaysInItsEnvironment(t *testing.T) {
	h := newPartnerHarness(t)
	const mac = "3c71bf4a12e0"
	if _, err := h.issueChip(t, john, "edge-labs-dev", mac, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.issueChip(t, john, "edge-labs-prod", mac, nil); errCode(err) != "env_mismatch" {
		t.Fatalf("same board in another environment: %v", err)
	}
	// Another partner's prefix makes another device; nothing of EDGE
	// Labs' is touched.
	resp, err := h.issueChip(t, tony, "acme-prod", mac, nil)
	if err != nil || resp.Device.ID != "BBB3C71BF4A12E0" {
		t.Fatalf("acme: %+v %v", resp, err)
	}
}

func TestPartnerEnvironmentConfigChecks(t *testing.T) {
	base := func() []service.EnvConfig { return slices.Clone(partnerEnvs) }
	for name, mutate := range map[string]func([]service.EnvConfig){
		"name is not partner-stage":      func(e []service.EnvConfig) { e[0].Name = "edgelabs-dev" },
		"stages of a partner differ":     func(e []service.EnvConfig) { e[1].DevicePrefix = "DVTX" },
		"one stage counts, one uses MAC": func(e []service.EnvConfig) { e[1].DeviceIDFromChip = false },
		"prefixes overlap":               func(e []service.EnvConfig) { e[2].DevicePrefix, e[3].DevicePrefix = "DVT", "DVT" },
		"partner without its own O=":     func(e []service.EnvConfig) { e[2].Organization = "" },
	} {
		envs := base()
		mutate(envs)
		_, err := service.New(service.Options{Store: store.NewMemory(), Archive: archive.NewMemory(),
			CAs: service.NewCAs(nil, archive.NewMemory(), nil), Envs: envs})
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}

// An intermediate CSR carries the partner's name unless told otherwise.
func TestCSRDefaultsToThePartnersOrganization(t *testing.T) {
	h := newPartnerHarness(t)
	r, err := h.svc.CACSR(context.Background(), admin, "acme-prod", model.CACSRRequest{CommonName: "ACME Intermediate CA prod"})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseCSR([]byte(r.CSRPEM))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(csr.Subject.Organization, []string{"ACME"}) {
		t.Errorf("subject %s", csr.Subject)
	}
}
