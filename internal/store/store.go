// Package store is the device and certificate registry.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/edge-labs/adl-signing-server/internal/model"
)

var (
	ErrNotFound = errors.New("not found")
	// ErrConflict means a conditional write lost: the item already exists
	// or was changed underneath us.
	ErrConflict = errors.New("conflict")
)

// ChipClaimedError is returned when a chip ID is already bound to another
// device. A physical chip can only ever carry one device identity.
type ChipClaimedError struct {
	ChipID   string
	DeviceID string
}

func (e *ChipClaimedError) Error() string {
	return fmt.Sprintf("chip %s is already assigned to device %s", e.ChipID, e.DeviceID)
}

// Store is implemented by the DynamoDB table in AWS and by Memory for tests
// and local mode.
type Store interface {
	// NextSequence atomically increments and returns the named counter.
	NextSequence(ctx context.Context, name string) (int64, error)
	// EnsureSequenceAtLeast raises the counter to n if it is lower.
	EnsureSequenceAtLeast(ctx context.Context, name string, n int64) error

	// CreateDevice inserts a new device (Version must be 0) and claims
	// its chip ID if set. ErrConflict if the device exists.
	CreateDevice(ctx context.Context, d *model.Device) error
	GetDevice(ctx context.Context, id string) (*model.Device, error)
	// UpdateDevice writes d if the stored version equals d.Version, then
	// bumps d.Version. Claims the chip ID if set.
	UpdateDevice(ctx context.Context, d *model.Device) error
	ListDevices(ctx context.Context, env string) ([]*model.Device, error)
	DeviceIDForChip(ctx context.Context, chipID string) (string, error)

	PutCertificate(ctx context.Context, c *model.Certificate) error
	UpdateCertificate(ctx context.Context, c *model.Certificate) error
	GetCertificate(ctx context.Context, serial string) (*model.Certificate, error)
	ListCertificates(ctx context.Context, deviceID string) ([]*model.Certificate, error)
	ListRevoked(ctx context.Context, env string) ([]*model.Certificate, error)

	// ClaimNonce records a one-time auth nonce; ErrConflict if seen before.
	ClaimNonce(ctx context.Context, nonce string, expires time.Time) error

	PutAudit(ctx context.Context, e *model.AuditEvent) error
	ListAudit(ctx context.Context, day time.Time) ([]*model.AuditEvent, error)
}

// DayKey is the partition used for audit events.
func DayKey(t time.Time) string { return t.UTC().Format("2006-01-02") }
