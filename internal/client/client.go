// Package client talks to the signing server on behalf of the adl CLI.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/edge-labs/adl-signing-server/internal/auth"
	"github.com/edge-labs/adl-signing-server/internal/model"
)

// Server is one signing server: where it is and how to sign in to it.
type Server struct {
	URL string `json:"url"`
	// Region is the STS region tokens are signed for; it must be one the
	// server accepts (normally the region it is deployed in).
	Region   string `json:"region"`
	Audience string `json:"audience"`
	// Profile is the AWS profile to take credentials from (SSO etc).
	Profile string `json:"profile,omitempty"`
	// Local talks to `adl-signer serve -local-insecure`.
	Local bool `json:"local,omitempty"`
}

// Config is stored in ~/.config/adl/config.json by `adl configure`. The
// embedded Server is the default one.
type Config struct {
	Server
	// Partner is the manufacturing partner to act for by default, for
	// people who may act for several (AutorQ staff). Partner staff never
	// need it: their identity only reaches their own environments.
	Partner string `json:"partner,omitempty"`
	// Stages holds one server per stage (dev, prod), for deployments that
	// run a signer per stage. --stage picks the server; the default one
	// is the fallback.
	Stages map[string]*Server `json:"stages,omitempty"`
}

// ForStage returns the server to use for want, a stage (prod) or a full
// environment name (edge-labs-prod). A stage server without a profile
// uses the default one's.
func (c *Config) ForStage(want string) (*Server, error) {
	if want != "" {
		for stage, s := range c.Stages {
			if s == nil || (want != stage && !strings.HasSuffix(want, "-"+stage)) {
				continue
			}
			out := *s
			if out.Profile == "" {
				out.Profile = c.Profile
			}
			return &out, nil
		}
	}
	if c.URL == "" {
		stages := make([]string, 0, len(c.Stages))
		for s := range c.Stages {
			stages = append(stages, s)
		}
		sort.Strings(stages)
		if want == "" {
			return nil, fmt.Errorf("pass --stage to pick a server (configured: %s)", strings.Join(stages, ", "))
		}
		return nil, fmt.Errorf("no server configured for %s (configured: %s); run `adl configure --stage ...`", want, strings.Join(stages, ", "))
	}
	out := c.Server
	return &out, nil
}

// ConfigPath is where the CLI keeps its config.
func ConfigPath() (string, error) {
	if p := os.Getenv("ADL_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "adl", "config.json"), nil
}

// LoadConfig reads the config file and applies ADL_* overrides.
func LoadConfig() (*Config, error) {
	c := &Config{}
	path, err := ConfigPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	for env, dst := range map[string]*string{"ADL_URL": &c.URL, "ADL_REGION": &c.Region, "ADL_AUDIENCE": &c.Audience, "ADL_PROFILE": &c.Profile, "ADL_PARTNER": &c.Partner} {
		if v := os.Getenv(env); v != "" {
			*dst = v
		}
	}
	if c.URL == "" && len(c.Stages) == 0 {
		return nil, errors.New("no server configured; run `adl configure --url https://...` (ask your admin for the values)")
	}
	return c, nil
}

// Save writes the config with owner-only permissions.
func (c *Config) Save() (string, error) {
	path, err := ConfigPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	return path, os.WriteFile(path, append(data, '\n'), 0o600)
}

type tokenSource interface {
	Token(ctx context.Context, method, requestURI string, body []byte) (string, error)
}

type Client struct {
	base   *url.URL
	http   *http.Client
	tokens tokenSource
	local  bool
	// LocalPrincipal names the caller in local mode.
	LocalPrincipal string
}

// New builds a client. In AWS mode it loads credentials the same way the
// AWS CLI does (profile, SSO cache, env vars, instance role).
func New(ctx context.Context, cfg *Server) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.URL, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("bad server url %q", cfg.URL)
	}
	if u.Scheme != "https" && !(cfg.Local || isLoopback(u.Hostname())) {
		return nil, fmt.Errorf("server url must be https (got %s)", u.Scheme)
	}
	c := &Client{base: u, http: &http.Client{Timeout: 60 * time.Second}, local: cfg.Local}
	if cfg.Local {
		c.LocalPrincipal = os.Getenv("USER")
		return c, nil
	}
	if cfg.Region == "" || cfg.Audience == "" {
		return nil, errors.New("config is missing region or audience; run `adl configure`")
	}
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(cfg.Region)}
	if cfg.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.Profile))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load aws credentials: %w", err)
	}
	c.tokens = &auth.TokenSigner{Credentials: awsCfg.Credentials, Region: cfg.Region, Audience: cfg.Audience}
	return c, nil
}

// NewWithTokens is for tests: any token source, any http client.
func NewWithTokens(base string, ts tokenSource, hc *http.Client) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return nil, err
	}
	return &Client{base: u, http: hc, tokens: ts, local: ts == nil}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// APIError is a non-2xx response from the server.
type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
	Details   map[string]string
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("%s (%d %s)", e.Message, e.Status, e.Code)
	if e.RequestID != "" {
		s += " [request " + e.RequestID + "]"
	}
	return s
}

// IsCode reports whether err is an APIError with the given code.
func IsCode(err error, code string) (*APIError, bool) {
	var ae *APIError
	if errors.As(err, &ae) && ae.Code == code {
		return ae, true
	}
	return nil, false
}

func (c *Client) raw(ctx context.Context, method, path string, q url.Values, in any) ([]byte, string, error) {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return nil, "", err
		}
	}
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + path
	u.RawQuery = q.Encode()

	attempts := 1
	if method == http.MethodGet {
		attempts = 3
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i) * 500 * time.Millisecond)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
		if err != nil {
			return nil, "", err
		}
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("User-Agent", "adl-cli")
		if c.local {
			req.Header.Set(auth.HeaderLocalPrincipal, c.LocalPrincipal)
		} else {
			// A fresh token per attempt: each is single use.
			tok, err := c.tokens.Token(ctx, method, u.RequestURI(), body)
			if err != nil {
				return nil, "", err
			}
			req.Header.Set(auth.HeaderAuth, tok)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return data, resp.Header.Get("Content-Type"), nil
		}
		var er model.ErrorResponse
		_ = json.Unmarshal(data, &er)
		if er.Error == "" {
			er.Error = strings.TrimSpace(string(data))
			if er.Error == "" {
				er.Error = http.StatusText(resp.StatusCode)
			}
		}
		lastErr = &APIError{Status: resp.StatusCode, Code: er.Code, Message: er.Error, RequestID: er.RequestID, Details: er.Details}
		if resp.StatusCode < 500 {
			break
		}
	}
	return nil, "", lastErr
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, in, out any) error {
	data, _, err := c.raw(ctx, method, path, q, in)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *Client) WhoAmI(ctx context.Context) (*model.WhoAmI, error) {
	var out model.WhoAmI
	return &out, c.do(ctx, http.MethodGet, "/v1/whoami", nil, nil, &out)
}

func (c *Client) Issue(ctx context.Context, req model.IssueRequest) (*model.IssueResponse, error) {
	var out model.IssueResponse
	return &out, c.do(ctx, http.MethodPost, "/v1/devices", nil, req, &out)
}

func (c *Client) ListDevices(ctx context.Context, env string) (*model.DeviceList, error) {
	q := url.Values{}
	if env != "" {
		q.Set("env", env)
	}
	var out model.DeviceList
	return &out, c.do(ctx, http.MethodGet, "/v1/devices", q, nil, &out)
}

func (c *Client) GetDevice(ctx context.Context, id string) (*model.DeviceDetail, error) {
	var out model.DeviceDetail
	return &out, c.do(ctx, http.MethodGet, "/v1/devices/"+url.PathEscape(id), nil, nil, &out)
}

func (c *Client) Bundle(ctx context.Context, id, serial string, includeKey bool) (*model.Bundle, error) {
	q := url.Values{}
	if serial != "" {
		q.Set("serial", serial)
	}
	if includeKey {
		q.Set("include_key", "true")
	}
	var out model.Bundle
	return &out, c.do(ctx, http.MethodGet, "/v1/devices/"+url.PathEscape(id)+"/bundle", q, nil, &out)
}

func (c *Client) Provisioned(ctx context.Context, id string, req model.ProvisionRequest) (*model.Device, error) {
	var out model.Device
	return &out, c.do(ctx, http.MethodPost, "/v1/devices/"+url.PathEscape(id)+"/provisioned", nil, req, &out)
}

func (c *Client) Revoke(ctx context.Context, id string, req model.RevokeRequest) (*model.DeviceDetail, error) {
	var out model.DeviceDetail
	return &out, c.do(ctx, http.MethodPost, "/v1/devices/"+url.PathEscape(id)+"/revoke", nil, req, &out)
}

func (c *Client) CAStatus(ctx context.Context, env string) (*model.CAStatus, error) {
	var out model.CAStatus
	return &out, c.do(ctx, http.MethodGet, "/v1/ca/"+url.PathEscape(env), nil, nil, &out)
}

func (c *Client) CACSR(ctx context.Context, env string, req model.CACSRRequest) (*model.CACSRResponse, error) {
	var out model.CACSRResponse
	return &out, c.do(ctx, http.MethodPost, "/v1/ca/"+url.PathEscape(env)+"/csr", nil, req, &out)
}

func (c *Client) CAInstall(ctx context.Context, env string, req model.CAInstallRequest) (*model.CAStatus, error) {
	var out model.CAStatus
	return &out, c.do(ctx, http.MethodPut, "/v1/ca/"+url.PathEscape(env)+"/certificate", nil, req, &out)
}

func (c *Client) CRL(ctx context.Context, env string) ([]byte, error) {
	data, _, err := c.raw(ctx, http.MethodGet, "/v1/ca/"+url.PathEscape(env)+"/crl", nil, nil)
	return data, err
}

func (c *Client) Import(ctx context.Context, req model.ImportRequest) (*model.DeviceDetail, error) {
	var out model.DeviceDetail
	return &out, c.do(ctx, http.MethodPost, "/v1/admin/import", nil, req, &out)
}

func (c *Client) Audit(ctx context.Context, day string) (*model.AuditList, error) {
	q := url.Values{}
	if day != "" {
		q.Set("day", day)
	}
	var out model.AuditList
	return &out, c.do(ctx, http.MethodGet, "/v1/audit", q, nil, &out)
}
