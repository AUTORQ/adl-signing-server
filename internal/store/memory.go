package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/edge-labs/adl-signing-server/internal/model"
)

// Memory is a Store kept in process memory.
type Memory struct {
	mu      sync.Mutex
	seq     map[string]int64
	devices map[string]model.Device
	chips   map[string]string
	certs   map[string]model.Certificate
	audit   []model.AuditEvent
	nonces  map[string]time.Time
}

func NewMemory() *Memory {
	return &Memory{
		seq:     map[string]int64{},
		devices: map[string]model.Device{},
		chips:   map[string]string{},
		certs:   map[string]model.Certificate{},
		nonces:  map[string]time.Time{},
	}
}

func (m *Memory) NextSequence(_ context.Context, name string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq[name]++
	return m.seq[name], nil
}

func (m *Memory) EnsureSequenceAtLeast(_ context.Context, name string, n int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seq[name] < n {
		m.seq[name] = n
	}
	return nil
}

func (m *Memory) claimLocked(chip, id string) error {
	if chip == "" {
		return nil
	}
	if owner, ok := m.chips[chip]; ok && owner != id {
		return &ChipClaimedError{ChipID: chip, DeviceID: owner}
	}
	return nil
}

func (m *Memory) CreateDevice(_ context.Context, d *model.Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.devices[d.ID]; ok {
		return ErrConflict
	}
	if err := m.claimLocked(d.ChipID, d.ID); err != nil {
		return err
	}
	d.Version = 1
	m.devices[d.ID] = cloneDevice(*d)
	if d.ChipID != "" {
		m.chips[d.ChipID] = d.ID
	}
	return nil
}

func (m *Memory) GetDevice(_ context.Context, id string) (*model.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := cloneDevice(d)
	return &c, nil
}

func (m *Memory) UpdateDevice(_ context.Context, d *model.Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.devices[d.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Version != d.Version {
		return ErrConflict
	}
	if err := m.claimLocked(d.ChipID, d.ID); err != nil {
		return err
	}
	d.Version++
	m.devices[d.ID] = cloneDevice(*d)
	if d.ChipID != "" {
		m.chips[d.ChipID] = d.ID
	}
	return nil
}

func (m *Memory) ListDevices(_ context.Context, env string) ([]*model.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*model.Device
	for _, d := range m.devices {
		if env == "" || d.Env == env {
			c := cloneDevice(d)
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) DeviceIDForChip(_ context.Context, chipID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.chips[chipID]
	if !ok {
		return "", ErrNotFound
	}
	return id, nil
}

func (m *Memory) PutCertificate(_ context.Context, c *model.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.certs[c.Serial]; ok {
		return ErrConflict
	}
	m.certs[c.Serial] = *c
	return nil
}

func (m *Memory) UpdateCertificate(_ context.Context, c *model.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.certs[c.Serial]; !ok {
		return ErrNotFound
	}
	m.certs[c.Serial] = *c
	return nil
}

func (m *Memory) GetCertificate(_ context.Context, serial string) (*model.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.certs[serial]
	if !ok {
		return nil, ErrNotFound
	}
	return &c, nil
}

func (m *Memory) ListCertificates(_ context.Context, deviceID string) ([]*model.Certificate, error) {
	return m.filterCerts(func(c model.Certificate) bool { return c.DeviceID == deviceID }), nil
}

func (m *Memory) ListRevoked(_ context.Context, env string) ([]*model.Certificate, error) {
	return m.filterCerts(func(c model.Certificate) bool { return c.Env == env && c.Status == model.CertRevoked }), nil
}

func (m *Memory) filterCerts(keep func(model.Certificate) bool) []*model.Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*model.Certificate
	for _, c := range m.certs {
		if keep(c) {
			c := c
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.Before(out[j].IssuedAt) })
	return out
}

func (m *Memory) ClaimNonce(_ context.Context, nonce string, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, exp := range m.nonces {
		if now.After(exp) {
			delete(m.nonces, k)
		}
	}
	if _, ok := m.nonces[nonce]; ok {
		return ErrConflict
	}
	m.nonces[nonce] = expires
	return nil
}

func (m *Memory) PutAudit(_ context.Context, e *model.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = append(m.audit, *e)
	return nil
}

func (m *Memory) ListAudit(_ context.Context, day time.Time) ([]*model.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := DayKey(day)
	var out []*model.AuditEvent
	for _, e := range m.audit {
		if DayKey(e.Time) == key {
			e := e
			out = append(out, &e)
		}
	}
	return out, nil
}

func cloneDevice(d model.Device) model.Device {
	if d.Labels != nil {
		l := make(map[string]string, len(d.Labels))
		for k, v := range d.Labels {
			l[k] = v
		}
		d.Labels = l
	}
	return d
}
