// Package model holds the records persisted by the registry and the JSON
// shapes exchanged between the server and the adl CLI.
package model

import "time"

// DeviceStatus tracks where a device is in its lifecycle.
type DeviceStatus string

const (
	// DevicePending means the device record exists but no certificate has
	// been recorded yet (an issue call failed part way through).
	DevicePending DeviceStatus = "pending"
	// DeviceIssued means a certificate was issued but nobody has confirmed
	// it was written to hardware. Developer devices normally stay here.
	DeviceIssued DeviceStatus = "issued"
	// DeviceProvisioned means an end-of-line station flashed the
	// certificate onto the chip and reported success.
	DeviceProvisioned DeviceStatus = "provisioned"
	// DeviceRevoked means every certificate for the device is revoked.
	DeviceRevoked DeviceStatus = "revoked"
)

// CertStatus is the status of a single issued certificate.
type CertStatus string

const (
	CertActive  CertStatus = "active"
	CertRevoked CertStatus = "revoked"
)

// Device is one physical (or development) unit identified by its device ID,
// which is also the certificate common name.
type Device struct {
	ID              string            `json:"device_id" dynamodbav:"device_id"`
	Env             string            `json:"env" dynamodbav:"env"`
	Status          DeviceStatus      `json:"status" dynamodbav:"status"`
	ChipID          string            `json:"chip_id,omitempty" dynamodbav:"chip_id,omitempty"`
	Owner           string            `json:"owner" dynamodbav:"owner"`
	CurrentSerial   string            `json:"current_serial,omitempty" dynamodbav:"current_serial,omitempty"`
	Labels          map[string]string `json:"labels,omitempty" dynamodbav:"labels,omitempty"`
	CreatedAt       time.Time         `json:"created_at" dynamodbav:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at" dynamodbav:"updated_at"`
	ProvisionedAt   *time.Time        `json:"provisioned_at,omitempty" dynamodbav:"provisioned_at,omitempty"`
	ProvisionedBy   string            `json:"provisioned_by,omitempty" dynamodbav:"provisioned_by,omitempty"`
	Station         string            `json:"station,omitempty" dynamodbav:"station,omitempty"`
	FirmwareVersion string            `json:"firmware_version,omitempty" dynamodbav:"firmware_version,omitempty"`
	Notes           string            `json:"notes,omitempty" dynamodbav:"notes,omitempty"`
	// Version is used for optimistic locking in the registry.
	Version int64 `json:"version" dynamodbav:"version"`
}

// Certificate is the registry record for one issued certificate. The PEM
// itself lives in the archive bucket under ArchivePrefix.
type Certificate struct {
	Serial            string     `json:"serial" dynamodbav:"serial"`
	DeviceID          string     `json:"device_id" dynamodbav:"device_id"`
	Env               string     `json:"env" dynamodbav:"env"`
	Status            CertStatus `json:"status" dynamodbav:"status"`
	Subject           string     `json:"subject" dynamodbav:"subject"`
	Issuer            string     `json:"issuer" dynamodbav:"issuer"`
	FingerprintSHA256 string     `json:"fingerprint_sha256" dynamodbav:"fingerprint_sha256"`
	KeyAlgorithm      string     `json:"key_algorithm" dynamodbav:"key_algorithm"`
	NotBefore         time.Time  `json:"not_before" dynamodbav:"not_before"`
	NotAfter          time.Time  `json:"not_after" dynamodbav:"not_after"`
	IssuedAt          time.Time  `json:"issued_at" dynamodbav:"issued_at"`
	IssuedBy          string     `json:"issued_by" dynamodbav:"issued_by"`
	KeyEscrowed       bool       `json:"key_escrowed" dynamodbav:"key_escrowed"`
	Imported          bool       `json:"imported,omitempty" dynamodbav:"imported,omitempty"`
	ArchivePrefix     string     `json:"archive_prefix" dynamodbav:"archive_prefix"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty" dynamodbav:"revoked_at,omitempty"`
	RevokedBy         string     `json:"revoked_by,omitempty" dynamodbav:"revoked_by,omitempty"`
	RevocationReason  string     `json:"revocation_reason,omitempty" dynamodbav:"revocation_reason,omitempty"`
}

// AuditEvent records a security relevant action. Every issuance, key
// retrieval, revocation and CA change produces one.
type AuditEvent struct {
	ID        string            `json:"id" dynamodbav:"id"`
	Time      time.Time         `json:"time" dynamodbav:"time"`
	Actor     string            `json:"actor" dynamodbav:"actor"`
	ActorARN  string            `json:"actor_arn" dynamodbav:"actor_arn"`
	Action    string            `json:"action" dynamodbav:"action"`
	Env       string            `json:"env,omitempty" dynamodbav:"env,omitempty"`
	DeviceID  string            `json:"device_id,omitempty" dynamodbav:"device_id,omitempty"`
	Serial    string            `json:"serial,omitempty" dynamodbav:"serial,omitempty"`
	RequestID string            `json:"request_id,omitempty" dynamodbav:"request_id,omitempty"`
	Detail    map[string]string `json:"detail,omitempty" dynamodbav:"detail,omitempty"`
}
