// Package service implements the signing server's operations. It is the
// only place that decides who may do what; the HTTP layer just decodes
// requests and calls in here.
package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/edge-labs/adl-signing-server/internal/archive"
	"github.com/edge-labs/adl-signing-server/internal/auth"
	"github.com/edge-labs/adl-signing-server/internal/model"
	"github.com/edge-labs/adl-signing-server/internal/pki"
	"github.com/edge-labs/adl-signing-server/internal/store"
)

// EnvConfig is the per environment policy (dev, prod, ...).
type EnvConfig struct {
	Name string
	// DevicePrefix and DeviceIDDigits shape allocated IDs: DVTADL + 017.
	// Environments with the same prefix share one counter, which is how
	// the legacy numbering worked.
	DevicePrefix   string
	DeviceIDDigits int
	Validity       time.Duration
	// AllowKeyEscrow lets clients upload the private key for safekeeping.
	// On for dev so people stop losing keys, off for prod where keys
	// should only ever exist on the device.
	AllowKeyEscrow bool
	// RequireChipID refuses certificates that are not bound to a chip.
	// On for prod, so prod identities only ever exist for real hardware.
	RequireChipID bool
	CRLValidity   time.Duration
}

type Options struct {
	Store        store.Store
	Archive      archive.Store
	CAs          *CAs
	Envs         []EnvConfig
	Organization string
	// DeviceIDPattern restricts caller supplied IDs.
	DeviceIDPattern *regexp.Regexp
	Now             func() time.Time
	Log             *slog.Logger
}

type Service struct {
	store   store.Store
	archive archive.Store
	cas     *CAs
	envs    map[string]EnvConfig
	org     string
	idRE    *regexp.Regexp
	now     func() time.Time
	log     *slog.Logger
}

var (
	DefaultDeviceIDPattern = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]{2,31}$`)
	labelKeyRE             = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)
	chipRE                 = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
	envNameRE              = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}$`)
)

func New(o Options) (*Service, error) {
	if o.Store == nil || o.Archive == nil || o.CAs == nil {
		return nil, errors.New("service: store, archive and CAs are required")
	}
	envs := map[string]EnvConfig{}
	for _, e := range o.Envs {
		if !envNameRE.MatchString(e.Name) {
			return nil, fmt.Errorf("service: bad environment name %q", e.Name)
		}
		if e.DevicePrefix == "" || e.Validity <= 0 {
			return nil, fmt.Errorf("service: env %s needs a device prefix and validity", e.Name)
		}
		if e.DeviceIDDigits == 0 {
			e.DeviceIDDigits = 3
		}
		if e.CRLValidity == 0 {
			e.CRLValidity = 7 * 24 * time.Hour
		}
		envs[e.Name] = e
	}
	if len(envs) == 0 {
		return nil, errors.New("service: no environments configured")
	}
	s := &Service{store: o.Store, archive: o.Archive, cas: o.CAs, envs: envs, org: o.Organization,
		idRE: o.DeviceIDPattern, now: o.Now, log: o.Log}
	if s.idRE == nil {
		s.idRE = DefaultDeviceIDPattern
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	return s, nil
}

// Envs lists configured environment names.
func (s *Service) Envs() []string {
	out := make([]string, 0, len(s.envs))
	for k := range s.envs {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (s *Service) env(name string) (EnvConfig, error) {
	e, ok := s.envs[name]
	if !ok {
		return e, badRequest("unknown environment %q (have %s)", name, strings.Join(s.Envs(), ", "))
	}
	return e, nil
}

func require(p *auth.Principal, perm string) error {
	if !p.Can(perm) {
		return forbidden(perm)
	}
	return nil
}

// NormalizeChipID lowercases and strips separators from a MAC / chip ID.
func NormalizeChipID(s string) string {
	r := strings.NewReplacer(":", "", "-", "", " ", "")
	return strings.ToLower(r.Replace(strings.TrimSpace(s)))
}

func (s *Service) checkChip(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	c := NormalizeChipID(raw)
	if !chipRE.MatchString(c) {
		return "", badRequest("chip_id %q is not a hex MAC/chip id", raw)
	}
	return c, nil
}

func checkLabels(l map[string]string) error {
	if len(l) > 16 {
		return badRequest("at most 16 labels")
	}
	for k, v := range l {
		if !labelKeyRE.MatchString(k) {
			return badRequest("bad label key %q", k)
		}
		if len(v) > 128 {
			return badRequest("label %q is too long", k)
		}
	}
	return nil
}

// sequenceNumber extracts 17 from DVTADL017 for prefix DVTADL.
func sequenceNumber(prefix, id string) (int64, bool) {
	rest, ok := strings.CutPrefix(id, prefix)
	if !ok || rest == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	return n, err == nil && n > 0
}

func seqName(prefix string) string { return "device-id:" + prefix }

func mapStoreErr(err error) error {
	var cc *store.ChipClaimedError
	switch {
	case errors.As(err, &cc):
		return conflict("chip_already_assigned", map[string]string{"chip_id": cc.ChipID, "device_id": cc.DeviceID},
			"chip %s is already assigned to device %s", cc.ChipID, cc.DeviceID)
	case errors.Is(err, store.ErrConflict):
		return conflict("concurrent_update", nil, "record changed while we were working on it, retry")
	}
	return err
}

func (s *Service) issuer(ctx context.Context, env string) (*pki.Issuer, error) {
	iss, err := s.cas.Issuer(ctx, env)
	if errors.Is(err, ErrCANotConfigured) {
		return nil, unavailable("ca_not_configured", "the %s CA certificate has not been installed yet (see docs/ca-ceremony.md)", env)
	}
	return iss, err
}

// Issue signs a device CSR, records it and archives the result.
func (s *Service) Issue(ctx context.Context, p *auth.Principal, req model.IssueRequest) (*model.IssueResponse, error) {
	env, err := s.env(req.Env)
	if err != nil {
		return nil, err
	}
	if err := require(p, env.Name+":issue"); err != nil {
		return nil, err
	}
	csr, err := pki.ParseCSR([]byte(req.CSR))
	if err != nil {
		return nil, badRequest("%v", err)
	}
	var escrowPEM []byte
	if req.PrivateKey != "" {
		if !env.AllowKeyEscrow {
			return nil, badRequest("key escrow is disabled for %s; keys for this environment must stay on the device", env.Name)
		}
		key, err := pki.ParsePrivateKey([]byte(req.PrivateKey))
		if err != nil {
			return nil, badRequest("private_key: %v", err)
		}
		if !key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(csr.PublicKey) {
			return nil, badRequest("private_key does not match the CSR")
		}
		if escrowPEM, err = pki.EncodePrivateKey(key); err != nil {
			return nil, err
		}
	}
	chip, err := s.checkChip(req.ChipID)
	if err != nil {
		return nil, err
	}
	// New devices must arrive with their chip; a replacement can lean on
	// the chip already recorded (checked once the device is loaded).
	if env.RequireChipID && chip == "" && !req.Replace {
		return nil, badRequest("%s certificates must be bound to a chip; chip_id is required", env.Name)
	}
	if err := checkLabels(req.Labels); err != nil {
		return nil, err
	}
	iss, err := s.issuer(ctx, env.Name)
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	var dev *model.Device
	replaced := ""
	if req.DeviceID == "" {
		if req.Replace {
			return nil, badRequest("replace needs a device_id")
		}
		if dev, err = s.allocate(ctx, p, env, chip, req.Labels, now); err != nil {
			return nil, err
		}
	} else {
		id := req.DeviceID
		if !s.idRE.MatchString(id) {
			return nil, badRequest("device_id %q does not match %s", id, s.idRE)
		}
		dev, err = s.store.GetDevice(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			// Numbers in the managed range come from the allocator, so
			// nobody can claim DVTADL99999 and push the counter out.
			if _, managed := sequenceNumber(env.DevicePrefix, id); managed && !p.Can("admin:import") {
				return nil, badRequest("ids starting with %s are allocated by the server; leave device_id empty", env.DevicePrefix)
			}
			dev = &model.Device{ID: id, Env: env.Name, Status: model.DevicePending, ChipID: chip,
				Owner: p.Name(), Labels: req.Labels, CreatedAt: now, UpdatedAt: now}
			if err := s.store.CreateDevice(ctx, dev); err != nil {
				if errors.Is(err, store.ErrConflict) {
					return nil, conflict("device_exists", map[string]string{"device_id": id}, "device %s was just created by someone else", id)
				}
				return nil, mapStoreErr(err)
			}
			// Keep the allocator from handing this number out later.
			if n, ok := sequenceNumber(env.DevicePrefix, id); ok {
				if err := s.store.EnsureSequenceAtLeast(ctx, seqName(env.DevicePrefix), n); err != nil {
					return nil, err
				}
			}
		case err != nil:
			return nil, err
		default:
			if dev.Env != env.Name {
				return nil, conflict("env_mismatch", map[string]string{"device_id": id, "env": dev.Env}, "device %s belongs to %s", id, dev.Env)
			}
			if !req.Replace && dev.Status != model.DevicePending {
				return nil, conflict("device_exists", map[string]string{"device_id": id, "status": string(dev.Status)},
					"device %s already has a certificate; pass replace to re-issue (the old one gets revoked)", id)
			}
			if (dev.Status == model.DeviceProvisioned || dev.Status == model.DeviceRevoked) && !p.Can(env.Name+":revoke") {
				return nil, forbidden(env.Name + ":revoke")
			}
			if chip != "" && dev.ChipID != "" && dev.ChipID != chip {
				return nil, conflict("chip_mismatch", map[string]string{"device_id": id, "chip_id": dev.ChipID},
					"device %s is bound to chip %s, not %s", id, dev.ChipID, chip)
			}
			if chip != "" {
				dev.ChipID = chip
			}
			for k, v := range req.Labels {
				if dev.Labels == nil {
					dev.Labels = map[string]string{}
				}
				dev.Labels[k] = v
			}
			replaced = dev.CurrentSerial
		}
	}

	if env.RequireChipID && dev.ChipID == "" {
		return nil, badRequest("%s certificates must be bound to a chip; chip_id is required", env.Name)
	}

	cert, err := iss.IssueDevice(dev.ID, csr.PublicKey, pki.DeviceProfile{
		Organization: s.org, Validity: env.Validity, Backdate: 5 * time.Minute,
	}, now)
	if err != nil {
		return nil, err
	}
	serial := pki.SerialHex(cert.SerialNumber)
	certPEM := pki.EncodeCertificates(cert)
	chainPEM := iss.ChainPEM()

	put := func(key string, data []byte, sensitive bool) error {
		return s.archive.Put(ctx, key, data, archive.PutOptions{ContentType: "application/x-pem-file", Sensitive: sensitive, NoOverwrite: true})
	}
	if err := put(archive.CertificateKey(env.Name, dev.ID, serial), certPEM, false); err != nil {
		return nil, err
	}
	if err := put(archive.ChainKey(env.Name, dev.ID, serial), chainPEM, false); err != nil {
		return nil, err
	}
	if escrowPEM != nil {
		if err := put(archive.EscrowKey(env.Name, dev.ID, serial), escrowPEM, true); err != nil {
			return nil, err
		}
	}

	rec := &model.Certificate{
		Serial: serial, DeviceID: dev.ID, Env: env.Name, Status: model.CertActive,
		Subject: cert.Subject.String(), Issuer: cert.Issuer.String(),
		FingerprintSHA256: pki.Fingerprint(cert), AuthorityKeyID: hex.EncodeToString(cert.AuthorityKeyId),
		KeyAlgorithm: pki.KeyAlgorithm(cert.PublicKey),
		NotBefore:    cert.NotBefore, NotAfter: cert.NotAfter, IssuedAt: now, IssuedBy: p.Name(),
		KeyEscrowed: escrowPEM != nil, ArchivePrefix: archive.CertificatePrefix(env.Name, dev.ID, serial),
	}
	if err := s.store.PutCertificate(ctx, rec); err != nil {
		return nil, err
	}

	dev.CurrentSerial = serial
	dev.Status = model.DeviceIssued
	dev.ProvisionedAt, dev.ProvisionedBy, dev.Station, dev.FirmwareVersion = nil, "", "", ""
	dev.UpdatedAt = now
	if err := s.store.UpdateDevice(ctx, dev); err != nil {
		// The device record moved under us, so this certificate never
		// became current. Kill it rather than leave a live orphan.
		s.log.ErrorContext(ctx, "device update failed after issuing, revoking new cert", "device_id", dev.ID, "serial", serial, "err", err)
		_ = s.revokeRecord(ctx, p, rec, "superseded", now)
		return nil, mapStoreErr(err)
	}
	if replaced != "" {
		if old, err := s.store.GetCertificate(ctx, replaced); err == nil && old.Status == model.CertActive {
			if err := s.revokeRecord(ctx, p, old, "superseded", now); err != nil {
				s.log.ErrorContext(ctx, "could not revoke superseded certificate", "serial", replaced, "err", err)
			}
		}
		s.refreshCRLBestEffort(ctx, env)
	}

	s.audit(ctx, p, "certificate.issue", env.Name, dev.ID, serial, map[string]string{
		"key_escrowed": strconv.FormatBool(escrowPEM != nil), "replaced": replaced, "chip_id": dev.ChipID,
		"fingerprint": rec.FingerprintSHA256,
	})
	return &model.IssueResponse{Device: *dev, Certificate: *rec, CertificatePEM: string(certPEM), ChainPEM: string(chainPEM)}, nil
}

func (s *Service) allocate(ctx context.Context, p *auth.Principal, env EnvConfig, chip string, labels map[string]string, now time.Time) (*model.Device, error) {
	// Retry past numbers that were taken by hand or by an import that did
	// not bump the counter.
	for range 50 {
		n, err := s.store.NextSequence(ctx, seqName(env.DevicePrefix))
		if err != nil {
			return nil, err
		}
		dev := &model.Device{
			ID: fmt.Sprintf("%s%0*d", env.DevicePrefix, env.DeviceIDDigits, n), Env: env.Name,
			Status: model.DevicePending, ChipID: chip, Owner: p.Name(), Labels: labels, CreatedAt: now, UpdatedAt: now,
		}
		err = s.store.CreateDevice(ctx, dev)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			return nil, mapStoreErr(err)
		}
		return dev, nil
	}
	return nil, errors.New("could not allocate a free device id after 50 attempts")
}

func (s *Service) getDevice(ctx context.Context, p *auth.Principal, id, action string) (*model.Device, error) {
	dev, err := s.store.GetDevice(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("device %s not found", id)
	}
	if err != nil {
		return nil, err
	}
	if err := require(p, dev.Env+":"+action); err != nil {
		return nil, err
	}
	return dev, nil
}

// GetDevice returns a device and every certificate it has had.
func (s *Service) GetDevice(ctx context.Context, p *auth.Principal, id string) (*model.DeviceDetail, error) {
	dev, err := s.getDevice(ctx, p, id, "read")
	if err != nil {
		return nil, err
	}
	certs, err := s.store.ListCertificates(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &model.DeviceDetail{Device: *dev, Certificates: []model.Certificate{}}
	for _, c := range certs {
		out.Certificates = append(out.Certificates, *c)
	}
	slices.SortFunc(out.Certificates, func(a, b model.Certificate) int { return a.IssuedAt.Compare(b.IssuedAt) })
	return out, nil
}

// ListDevices lists devices in env, or in every env the caller can read.
func (s *Service) ListDevices(ctx context.Context, p *auth.Principal, env string) (*model.DeviceList, error) {
	var envs []string
	if env != "" {
		if _, err := s.env(env); err != nil {
			return nil, err
		}
		if err := require(p, env+":read"); err != nil {
			return nil, err
		}
		envs = []string{env}
	} else {
		for _, e := range s.Envs() {
			if p.Can(e + ":read") {
				envs = append(envs, e)
			}
		}
		if len(envs) == 0 {
			return nil, forbidden("<env>:read")
		}
	}
	out := &model.DeviceList{Devices: []model.Device{}}
	for _, e := range envs {
		devs, err := s.store.ListDevices(ctx, e)
		if err != nil {
			return nil, err
		}
		for _, d := range devs {
			out.Devices = append(out.Devices, *d)
		}
	}
	slices.SortFunc(out.Devices, func(a, b model.Device) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// Bundle returns the cert, chain and (if asked, allowed and escrowed) the
// private key for a device. serial defaults to the current certificate.
func (s *Service) Bundle(ctx context.Context, p *auth.Principal, id, serial string, includeKey bool) (*model.Bundle, error) {
	dev, err := s.getDevice(ctx, p, id, "read")
	if err != nil {
		return nil, err
	}
	if serial == "" {
		serial = dev.CurrentSerial
	}
	if serial == "" {
		return nil, notFound("device %s has no certificate yet", id)
	}
	rec, err := s.store.GetCertificate(ctx, serial)
	if errors.Is(err, store.ErrNotFound) || (err == nil && rec.DeviceID != id) {
		return nil, notFound("certificate %s not found for %s", serial, id)
	}
	if err != nil {
		return nil, err
	}
	certPEM, err := s.archive.Get(ctx, archive.CertificateKey(rec.Env, id, serial))
	if err != nil {
		return nil, err
	}
	chainPEM, err := s.archive.Get(ctx, archive.ChainKey(rec.Env, id, serial))
	if err != nil && !errors.Is(err, archive.ErrNotFound) {
		return nil, err
	}
	b := &model.Bundle{DeviceID: id, Env: rec.Env, Serial: serial, CertificatePEM: string(certPEM), ChainPEM: string(chainPEM)}
	if includeKey {
		if err := require(p, rec.Env+":key-read"); err != nil {
			return nil, err
		}
		if !rec.KeyEscrowed {
			return nil, notFound("no escrowed key for %s serial %s", id, serial)
		}
		key, err := s.archive.Get(ctx, archive.EscrowKey(rec.Env, id, serial))
		if err != nil {
			return nil, err
		}
		b.PrivateKeyPEM = string(key)
		s.audit(ctx, p, "key.retrieve", rec.Env, id, serial, nil)
	}
	return b, nil
}

// MarkProvisioned is the last step of end-of-line: the station confirms
// the certificate is on the chip.
func (s *Service) MarkProvisioned(ctx context.Context, p *auth.Principal, id string, req model.ProvisionRequest) (*model.Device, error) {
	dev, err := s.getDevice(ctx, p, id, "provision")
	if err != nil {
		return nil, err
	}
	chip, err := s.checkChip(req.ChipID)
	if err != nil {
		return nil, err
	}
	if chip == "" || strings.TrimSpace(req.Station) == "" {
		return nil, badRequest("chip_id and station are required")
	}
	if len(req.Station) > 64 || len(req.FirmwareVersion) > 64 || len(req.Notes) > 512 {
		return nil, badRequest("station, firmware_version or notes too long")
	}
	if req.Serial == "" || req.Serial != dev.CurrentSerial {
		return nil, conflict("serial_mismatch", map[string]string{"current_serial": dev.CurrentSerial},
			"serial %q is not the current certificate for %s", req.Serial, id)
	}
	if dev.ChipID != "" && dev.ChipID != chip {
		return nil, conflict("chip_mismatch", map[string]string{"chip_id": dev.ChipID}, "device %s is bound to chip %s", id, dev.ChipID)
	}
	if dev.Status == model.DeviceProvisioned && dev.ChipID == chip {
		return dev, nil
	}
	rec, err := s.store.GetCertificate(ctx, req.Serial)
	if err != nil {
		return nil, err
	}
	if rec.Status != model.CertActive {
		return nil, conflict("certificate_revoked", nil, "certificate %s is revoked", req.Serial)
	}
	now := s.now().UTC()
	dev.ChipID = chip
	dev.Status = model.DeviceProvisioned
	dev.ProvisionedAt = &now
	dev.ProvisionedBy = p.Name()
	dev.Station = req.Station
	dev.FirmwareVersion = req.FirmwareVersion
	dev.Notes = req.Notes
	dev.UpdatedAt = now
	if err := s.store.UpdateDevice(ctx, dev); err != nil {
		return nil, mapStoreErr(err)
	}
	s.audit(ctx, p, "device.provisioned", dev.Env, id, req.Serial, map[string]string{
		"chip_id": chip, "station": req.Station, "firmware_version": req.FirmwareVersion,
	})
	return dev, nil
}

// Revoke revokes one or all active certificates of a device.
func (s *Service) Revoke(ctx context.Context, p *auth.Principal, id string, req model.RevokeRequest) (*model.DeviceDetail, error) {
	dev, err := s.getDevice(ctx, p, id, "revoke")
	if err != nil {
		return nil, err
	}
	if _, err := pki.ReasonCode(req.Reason); err != nil {
		return nil, badRequest("%v", err)
	}
	certs, err := s.store.ListCertificates(ctx, id)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	n := 0
	for _, c := range certs {
		if c.Status != model.CertActive || (req.Serial != "" && c.Serial != req.Serial) {
			continue
		}
		if err := s.revokeRecord(ctx, p, c, req.Reason, now); err != nil {
			return nil, err
		}
		n++
	}
	if n == 0 {
		return nil, notFound("no active certificate to revoke on %s", id)
	}
	if req.Serial == "" || req.Serial == dev.CurrentSerial {
		dev.Status = model.DeviceRevoked
		dev.UpdatedAt = now
		if err := s.store.UpdateDevice(ctx, dev); err != nil {
			return nil, mapStoreErr(err)
		}
	}
	env, _ := s.env(dev.Env)
	s.refreshCRLBestEffort(ctx, env)
	return s.GetDevice(ctx, p, id)
}

func (s *Service) revokeRecord(ctx context.Context, p *auth.Principal, c *model.Certificate, reason string, now time.Time) error {
	if reason == "" {
		reason = "unspecified"
	}
	c.Status = model.CertRevoked
	c.RevokedAt = &now
	c.RevokedBy = p.Name()
	c.RevocationReason = reason
	if err := s.store.UpdateCertificate(ctx, c); err != nil {
		return err
	}
	s.audit(ctx, p, "certificate.revoke", c.Env, c.DeviceID, c.Serial, map[string]string{"reason": reason})
	return nil
}

// CRL returns a DER CRL for env, re-signing it once it is past half its
// lifetime. Revocations re-sign immediately.
func (s *Service) CRL(ctx context.Context, envName string) ([]byte, error) {
	env, err := s.env(envName)
	if err != nil {
		return nil, err
	}
	der, err := s.archive.Get(ctx, archive.CRLKey(env.Name))
	if err == nil {
		if crl, perr := x509.ParseRevocationList(der); perr == nil {
			half := crl.ThisUpdate.Add(crl.NextUpdate.Sub(crl.ThisUpdate) / 2)
			if s.now().Before(half) {
				return der, nil
			}
		}
	} else if !errors.Is(err, archive.ErrNotFound) {
		return nil, err
	}
	return s.refreshCRL(ctx, env)
}

func (s *Service) refreshCRL(ctx context.Context, env EnvConfig) ([]byte, error) {
	iss, err := s.issuer(ctx, env.Name)
	if err != nil {
		return nil, err
	}
	revoked, err := s.store.ListRevoked(ctx, env.Name)
	if err != nil {
		return nil, err
	}
	ski := hex.EncodeToString(iss.Certificate().SubjectKeyId)
	var entries []pki.RevokedEntry
	for _, c := range revoked {
		// A CRL may only list certificates its issuer signed. Imported
		// legacy certs and certs from a rotated-out CA are skipped.
		if c.AuthorityKeyID != ski || c.RevokedAt == nil {
			continue
		}
		serial, err := pki.ParseSerialHex(c.Serial)
		if err != nil {
			continue
		}
		code, _ := pki.ReasonCode(c.RevocationReason)
		entries = append(entries, pki.RevokedEntry{Serial: serial, RevokedAt: *c.RevokedAt, Reason: code})
	}
	n, err := s.store.NextSequence(ctx, "crl:"+env.Name)
	if err != nil {
		return nil, err
	}
	der, err := iss.CreateCRL(entries, big.NewInt(n), s.now(), env.CRLValidity)
	if err != nil {
		return nil, err
	}
	if err := s.archive.Put(ctx, archive.CRLKey(env.Name), der, archive.PutOptions{ContentType: "application/pkix-crl"}); err != nil {
		return nil, err
	}
	return der, nil
}

func (s *Service) refreshCRLBestEffort(ctx context.Context, env EnvConfig) {
	if _, err := s.refreshCRL(ctx, env); err != nil {
		s.log.ErrorContext(ctx, "crl refresh failed", "env", env.Name, "err", err)
	}
}

// CAStatus is public: it tells people (and devices) what the CA looks like.
func (s *Service) CAStatus(ctx context.Context, envName string) (*model.CAStatus, error) {
	env, err := s.env(envName)
	if err != nil {
		return nil, err
	}
	out := &model.CAStatus{Env: env.Name}
	signer, err := s.cas.Signer(ctx, env.Name)
	if err != nil {
		return nil, err
	}
	out.KeyAlgorithm = pki.KeyAlgorithm(signer.Public())
	out.PublicKeySHA256, _ = pki.PublicKeyFingerprint(signer.Public())
	iss, err := s.cas.Issuer(ctx, env.Name)
	if errors.Is(err, ErrCANotConfigured) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	c := iss.Certificate()
	out.Configured = true
	out.Subject = c.Subject.String()
	out.Issuer = c.Issuer.String()
	out.NotBefore = c.NotBefore
	out.NotAfter = c.NotAfter
	out.FingerprintSHA256 = pki.Fingerprint(c)
	out.ChainPEM = string(iss.ChainPEM())
	return out, nil
}

// CACSR produces a CSR for the env's KMS key, to be signed offline by the
// AutorQ root.
func (s *Service) CACSR(ctx context.Context, p *auth.Principal, envName string, req model.CACSRRequest) (*model.CACSRResponse, error) {
	if err := require(p, "ca:admin"); err != nil {
		return nil, err
	}
	env, err := s.env(envName)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.CommonName) == "" {
		return nil, badRequest("common_name is required")
	}
	signer, err := s.cas.Signer(ctx, env.Name)
	if err != nil {
		return nil, err
	}
	subj := pkix.Name{CommonName: req.CommonName}
	if req.Organization != "" {
		subj.Organization = []string{req.Organization}
	}
	if req.OrganizationalUnit != "" {
		subj.OrganizationalUnit = []string{req.OrganizationalUnit}
	}
	if req.Country != "" {
		subj.Country = []string{req.Country}
	}
	csr, err := pki.CreateCSR(signer, subj)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, p, "ca.csr", env.Name, "", "", map[string]string{"subject": subj.String()})
	return &model.CACSRResponse{CSRPEM: string(csr)}, nil
}

// CAInstall installs the signed intermediate chain for env.
func (s *Service) CAInstall(ctx context.Context, p *auth.Principal, envName string, req model.CAInstallRequest) (*model.CAStatus, error) {
	if err := require(p, "ca:admin"); err != nil {
		return nil, err
	}
	env, err := s.env(envName)
	if err != nil {
		return nil, err
	}
	chain, err := pki.ParseCertificates([]byte(req.ChainPEM))
	if err != nil {
		return nil, badRequest("%v", err)
	}
	iss, err := s.cas.Install(ctx, env.Name, chain)
	if err != nil {
		return nil, badRequest("%v", err)
	}
	s.audit(ctx, p, "ca.install", env.Name, "", "", map[string]string{
		"subject": iss.Certificate().Subject.String(), "fingerprint": pki.Fingerprint(iss.Certificate()),
	})
	if _, err := s.refreshCRL(ctx, env); err != nil {
		s.log.ErrorContext(ctx, "initial crl failed", "env", env.Name, "err", err)
	}
	return s.CAStatus(ctx, env.Name)
}

// Import registers a certificate made by the old droplet scripts.
func (s *Service) Import(ctx context.Context, p *auth.Principal, req model.ImportRequest) (*model.DeviceDetail, error) {
	if err := require(p, "admin:import"); err != nil {
		return nil, err
	}
	env, err := s.env(req.Env)
	if err != nil {
		return nil, err
	}
	certs, err := pki.ParseCertificates([]byte(req.CertificatePEM))
	if err != nil {
		return nil, badRequest("certificate_pem: %v", err)
	}
	leaf := certs[0]
	id := leaf.Subject.CommonName
	if !s.idRE.MatchString(id) {
		return nil, badRequest("certificate CN %q is not a valid device id", id)
	}
	if req.ChainPEM != "" {
		chain, err := pki.ParseCertificates([]byte(req.ChainPEM))
		if err != nil {
			return nil, badRequest("chain_pem: %v", err)
		}
		if err := leaf.CheckSignatureFrom(chain[0]); err != nil {
			return nil, badRequest("certificate is not signed by the first certificate in chain_pem")
		}
	}
	var keyPEM []byte
	if req.PrivateKeyPEM != "" {
		if !env.AllowKeyEscrow {
			return nil, badRequest("key escrow is disabled for %s; import the certificate without its key", env.Name)
		}
		key, err := pki.ParsePrivateKey([]byte(req.PrivateKeyPEM))
		if err != nil {
			return nil, badRequest("private_key_pem: %v", err)
		}
		if err := pki.MatchesPublicKey(leaf, key.Public()); err != nil {
			return nil, badRequest("private key does not match certificate")
		}
		if keyPEM, err = pki.EncodePrivateKey(key); err != nil {
			return nil, err
		}
	}
	chip, err := s.checkChip(req.ChipID)
	if err != nil {
		return nil, err
	}
	serial := pki.SerialHex(leaf.SerialNumber)
	if _, err := s.store.GetCertificate(ctx, serial); err == nil {
		return nil, conflict("already_imported", map[string]string{"serial": serial, "device_id": id}, "certificate %s is already registered", serial)
	}

	now := s.now().UTC()
	dev, err := s.store.GetDevice(ctx, id)
	isNew := errors.Is(err, store.ErrNotFound)
	if err != nil && !isNew {
		return nil, err
	}
	if isNew {
		dev = &model.Device{ID: id, Env: env.Name, Status: model.DeviceIssued, ChipID: chip,
			Owner: "import:" + p.Name(), CreatedAt: leaf.NotBefore.UTC(), UpdatedAt: now,
			Labels: map[string]string{"source": "legacy-droplet"}}
	} else if dev.Env != env.Name {
		return nil, conflict("env_mismatch", map[string]string{"env": dev.Env}, "device %s already registered in %s", id, dev.Env)
	}

	put := func(key string, data []byte, sensitive bool) error {
		err := s.archive.Put(ctx, key, data, archive.PutOptions{ContentType: "application/x-pem-file", Sensitive: sensitive, NoOverwrite: true})
		if errors.Is(err, archive.ErrExists) {
			return nil
		}
		return err
	}
	if err := put(archive.CertificateKey(env.Name, id, serial), pki.EncodeCertificates(leaf), false); err != nil {
		return nil, err
	}
	if req.ChainPEM != "" {
		if err := put(archive.ChainKey(env.Name, id, serial), []byte(req.ChainPEM), false); err != nil {
			return nil, err
		}
	}
	if keyPEM != nil {
		if err := put(archive.EscrowKey(env.Name, id, serial), keyPEM, true); err != nil {
			return nil, err
		}
	}
	rec := &model.Certificate{
		Serial: serial, DeviceID: id, Env: env.Name, Status: model.CertActive,
		Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(),
		FingerprintSHA256: pki.Fingerprint(leaf), AuthorityKeyID: hex.EncodeToString(leaf.AuthorityKeyId),
		KeyAlgorithm: pki.KeyAlgorithm(leaf.PublicKey), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
		IssuedAt: leaf.NotBefore.UTC(), IssuedBy: "legacy", KeyEscrowed: keyPEM != nil, Imported: true,
		ArchivePrefix: archive.CertificatePrefix(env.Name, id, serial),
	}
	if err := s.store.PutCertificate(ctx, rec); err != nil {
		return nil, mapStoreErr(err)
	}

	// The newest certificate wins as "current".
	makeCurrent := dev.CurrentSerial == ""
	if !makeCurrent {
		if cur, err := s.store.GetCertificate(ctx, dev.CurrentSerial); err == nil && cur.NotBefore.Before(leaf.NotBefore) {
			makeCurrent = true
		}
	}
	if makeCurrent {
		dev.CurrentSerial = serial
	}
	if chip != "" && dev.ChipID == "" {
		dev.ChipID = chip
	}
	if req.Provisioned && dev.Status != model.DeviceProvisioned {
		dev.Status = model.DeviceProvisioned
		dev.ProvisionedAt = &now
		dev.ProvisionedBy = "legacy"
	}
	dev.UpdatedAt = now
	if isNew {
		err = s.store.CreateDevice(ctx, dev)
	} else {
		err = s.store.UpdateDevice(ctx, dev)
	}
	if err != nil {
		return nil, mapStoreErr(err)
	}
	if n, ok := sequenceNumber(env.DevicePrefix, id); ok {
		if err := s.store.EnsureSequenceAtLeast(ctx, seqName(env.DevicePrefix), n); err != nil {
			return nil, err
		}
	}
	s.audit(ctx, p, "certificate.import", env.Name, id, serial, map[string]string{"key_escrowed": strconv.FormatBool(keyPEM != nil)})
	return s.GetDevice(ctx, p, id)
}

// Audit lists audit events for one UTC day.
func (s *Service) Audit(ctx context.Context, p *auth.Principal, day time.Time) (*model.AuditList, error) {
	if err := require(p, "audit:read"); err != nil {
		return nil, err
	}
	evs, err := s.store.ListAudit(ctx, day)
	if err != nil {
		return nil, err
	}
	out := &model.AuditList{Events: []model.AuditEvent{}}
	for _, e := range evs {
		out.Events = append(out.Events, *e)
	}
	slices.SortFunc(out.Events, func(a, b model.AuditEvent) int { return a.Time.Compare(b.Time) })
	return out, nil
}

func (s *Service) audit(ctx context.Context, p *auth.Principal, action, env, deviceID, serial string, detail map[string]string) {
	for k, v := range detail {
		if v == "" {
			delete(detail, k)
		}
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	e := &model.AuditEvent{
		ID: hex.EncodeToString(id), Time: s.now().UTC(), Actor: p.Name(), ActorARN: p.ARN,
		Action: action, Env: env, DeviceID: deviceID, Serial: serial, RequestID: RequestID(ctx), Detail: detail,
	}
	s.log.InfoContext(ctx, "audit", "action", action, "actor", e.Actor, "actor_arn", e.ActorARN,
		"env", env, "device_id", deviceID, "serial", serial, "detail", detail)
	if err := s.store.PutAudit(ctx, e); err != nil {
		// The action already happened; the log line above is the backup.
		s.log.ErrorContext(ctx, "failed to persist audit event", "action", action, "err", err)
	}
}
