package model

import "time"

// IssueRequest asks the server to sign a device CSR.
type IssueRequest struct {
	Env string `json:"env"`
	// DeviceID is optional. When empty the server allocates the next ID
	// from the environment's sequence (e.g. DVTADL017).
	DeviceID string `json:"device_id,omitempty"`
	CSR      string `json:"csr"`
	// PrivateKey is the PEM private key to escrow. Only accepted for
	// environments with escrow enabled (dev by default).
	PrivateKey string            `json:"private_key,omitempty"`
	ChipID     string            `json:"chip_id,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	// Replace re-issues a certificate for an existing device and revokes
	// the previous one as superseded.
	Replace bool `json:"replace,omitempty"`
	// Move assigns a device that is in another stage of the same partner
	// (dev -> prod or back) to Env. Its certificates there are revoked
	// (cessationOfOperation) once the new one is issued, so a device is
	// only ever live in one stage. Needs revoke on the old environment.
	Move bool `json:"move,omitempty"`
}

type IssueResponse struct {
	Device         Device      `json:"device"`
	Certificate    Certificate `json:"certificate"`
	CertificatePEM string      `json:"certificate_pem"`
	ChainPEM       string      `json:"chain_pem"`
}

type DeviceDetail struct {
	Device       Device        `json:"device"`
	Certificates []Certificate `json:"certificates"`
}

type DeviceList struct {
	Devices []Device `json:"devices"`
}

type Bundle struct {
	DeviceID       string `json:"device_id"`
	Env            string `json:"env"`
	Serial         string `json:"serial"`
	CertificatePEM string `json:"certificate_pem"`
	ChainPEM       string `json:"chain_pem"`
	PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
}

// ProvisionRequest is sent by an end-of-line station once the certificate
// has been written to the chip and verified.
type ProvisionRequest struct {
	Serial          string `json:"serial"`
	ChipID          string `json:"chip_id"`
	Station         string `json:"station"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	Notes           string `json:"notes,omitempty"`
}

type RevokeRequest struct {
	// Serial limits the revocation to one certificate. When empty every
	// active certificate for the device is revoked.
	Serial string `json:"serial,omitempty"`
	Reason string `json:"reason"`
}

type CAStatus struct {
	Env               string    `json:"env"`
	Configured        bool      `json:"configured"`
	KeyAlgorithm      string    `json:"key_algorithm,omitempty"`
	PublicKeySHA256   string    `json:"public_key_sha256,omitempty"`
	Subject           string    `json:"subject,omitempty"`
	Issuer            string    `json:"issuer,omitempty"`
	NotBefore         time.Time `json:"not_before,omitempty"`
	NotAfter          time.Time `json:"not_after,omitempty"`
	FingerprintSHA256 string    `json:"fingerprint_sha256,omitempty"`
	ChainPEM          string    `json:"chain_pem,omitempty"`
}

type CACSRRequest struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
}

type CACSRResponse struct {
	CSRPEM string `json:"csr_pem"`
}

// CAInstallRequest installs the signed intermediate. ChainPEM must start
// with the intermediate for this environment followed by its issuers, ending
// with the root.
type CAInstallRequest struct {
	ChainPEM string `json:"chain_pem"`
}

// ImportRequest registers a certificate issued outside this system (the
// legacy droplet) so it shows up in the registry and its key is escrowed.
type ImportRequest struct {
	Env            string `json:"env"`
	CertificatePEM string `json:"certificate_pem"`
	ChainPEM       string `json:"chain_pem,omitempty"`
	PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
	ChipID         string `json:"chip_id,omitempty"`
	Provisioned    bool   `json:"provisioned,omitempty"`
}

type WhoAmI struct {
	ARN         string   `json:"arn"`
	Principal   string   `json:"principal"`
	Account     string   `json:"account"`
	Permissions []string `json:"permissions"`
	// Environments are the ones the caller may use, with what for.
	Environments []EnvAccess `json:"environments"`
}

// EnvAccess is one environment a caller may use.
type EnvAccess struct {
	Name    string   `json:"name"`
	Partner string   `json:"partner,omitempty"`
	Stage   string   `json:"stage"`
	Actions []string `json:"actions"`
}

type AuditList struct {
	Events []AuditEvent `json:"events"`
}

type ErrorResponse struct {
	Error     string            `json:"error"`
	Code      string            `json:"code"`
	RequestID string            `json:"request_id,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
}
