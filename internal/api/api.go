// Package api is the HTTP front end. It is a plain http.Handler so the same
// code serves the EC2 deployment directly and the Lambda deployment through
// the lambdahttp adapter.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/edge-labs/adl-signing-server/internal/auth"
	"github.com/edge-labs/adl-signing-server/internal/model"
	"github.com/edge-labs/adl-signing-server/internal/service"
)

const maxBody = 256 << 10

type Server struct {
	svc  *service.Service
	auth auth.Authenticator
	log  *slog.Logger
	mux  *http.ServeMux
}

// New wires the routes. Everything under /v1 needs authentication except
// the CA chain and CRL, which devices and relying parties fetch anonymously.
func New(svc *service.Service, authn auth.Authenticator, log *slog.Logger) http.Handler {
	s := &Server{svc: svc, auth: authn, log: log, mux: http.NewServeMux()}

	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("GET /v1/ca/{env}", s.caStatus)
	s.mux.HandleFunc("GET /v1/ca/{env}/chain.pem", s.caChain)
	s.mux.HandleFunc("GET /v1/ca/{env}/crl", s.crl)

	s.mux.HandleFunc("GET /v1/whoami", s.authed(s.whoami))
	s.mux.HandleFunc("POST /v1/ca/{env}/csr", s.authed(s.caCSR))
	s.mux.HandleFunc("PUT /v1/ca/{env}/certificate", s.authed(s.caInstall))
	s.mux.HandleFunc("POST /v1/devices", s.authed(s.issue))
	s.mux.HandleFunc("GET /v1/devices", s.authed(s.listDevices))
	s.mux.HandleFunc("GET /v1/devices/{id}", s.authed(s.getDevice))
	s.mux.HandleFunc("GET /v1/devices/{id}/bundle", s.authed(s.bundle))
	s.mux.HandleFunc("POST /v1/devices/{id}/provisioned", s.authed(s.provisioned))
	s.mux.HandleFunc("POST /v1/devices/{id}/revoke", s.authed(s.revoke))
	s.mux.HandleFunc("POST /v1/admin/import", s.authed(s.importCert))
	s.mux.HandleFunc("GET /v1/audit", s.authed(s.audit))

	return s.middleware(s.mux)
}

type ctxKey struct{}

var requestIDRE = regexp.MustCompile(`^[A-Za-z0-9._=-]{8,128}$`)

type statusWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.size += n
	return n, err
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rid := r.Header.Get("X-Request-Id")
		if !requestIDRE.MatchString(rid) {
			b := make([]byte, 12)
			_, _ = rand.Read(b)
			rid = hex.EncodeToString(b)
		}
		ctx := service.WithRequestID(r.Context(), rid)
		ctx = context.WithValue(ctx, ctxKey{}, &principalHolder{})
		r = r.WithContext(ctx)

		h := w.Header()
		h.Set("X-Request-Id", rid)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", "max-age=63072000")
		h.Set("Content-Security-Policy", "default-src 'none'")
		h.Set("Cache-Control", "no-store")

		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				s.log.ErrorContext(ctx, "panic", "err", rec, "stack", string(debug.Stack()))
				writeJSON(sw, http.StatusInternalServerError, model.ErrorResponse{Error: "internal error", Code: "internal", RequestID: rid})
			}
			s.log.InfoContext(ctx, "request", "request_id", rid, "method", r.Method, "path", r.URL.Path,
				"status", sw.status, "bytes", sw.size, "duration_ms", time.Since(start).Milliseconds(),
				"remote", r.RemoteAddr, "principal", principalName(r))
		}()
		next.ServeHTTP(sw, r)
	})
}

// principalHolder lets the access log line see who the authed handler
// resolved, without threading it back up the call stack.
type principalHolder struct{ p *auth.Principal }

func principalName(r *http.Request) string {
	if h, ok := r.Context().Value(ctxKey{}).(*principalHolder); ok && h.p != nil {
		return h.p.Name()
	}
	return ""
}

type authedHandler func(w http.ResponseWriter, r *http.Request, p *auth.Principal, body []byte)

func (s *Server) authed(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			s.writeErr(w, r, &service.Error{Status: http.StatusRequestEntityTooLarge, Code: "too_large", Msg: "request body too large"})
			return
		}
		p, err := s.auth.Authenticate(r.Context(), r, body)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrUnauthenticated):
				s.log.WarnContext(r.Context(), "authentication failed", "err", err)
				s.writeErr(w, r, &service.Error{Status: http.StatusUnauthorized, Code: "unauthenticated", Msg: err.Error()})
			case errors.Is(err, auth.ErrNotAuthorized):
				s.log.WarnContext(r.Context(), "authorization failed", "err", err)
				s.writeErr(w, r, &service.Error{Status: http.StatusForbidden, Code: "forbidden", Msg: err.Error()})
			default:
				s.log.ErrorContext(r.Context(), "authentication backend error", "err", err)
				s.writeErr(w, r, &service.Error{Status: http.StatusServiceUnavailable, Code: "auth_unavailable", Msg: "could not verify identity, try again"})
			}
			return
		}
		if holder, ok := r.Context().Value(ctxKey{}).(*principalHolder); ok {
			holder.p = p
		}
		h(w, r, p, body)
	}
}

func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	rid := service.RequestID(r.Context())
	var se *service.Error
	if errors.As(err, &se) {
		writeJSON(w, se.Status, model.ErrorResponse{Error: se.Msg, Code: se.Code, RequestID: rid, Details: se.Details})
		return
	}
	s.log.ErrorContext(r.Context(), "request failed", "err", err)
	writeJSON(w, http.StatusInternalServerError, model.ErrorResponse{Error: "internal error", Code: "internal", RequestID: rid})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func decode(body []byte, v any) error {
	if len(strings.TrimSpace(string(body))) == 0 {
		return &service.Error{Status: http.StatusBadRequest, Code: "bad_request", Msg: "request body is required"}
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &service.Error{Status: http.StatusBadRequest, Code: "bad_request", Msg: fmt.Sprintf("invalid json: %v", err)}
	}
	return nil
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	// No environment list: in a shared deployment it would name every
	// partner to anyone on the internet. Signed-in callers get theirs
	// from /v1/whoami.
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) caStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.svc.CAStatus(r.Context(), r.PathValue("env"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) caChain(w http.ResponseWriter, r *http.Request) {
	st, err := s.svc.CAStatus(r.Context(), r.PathValue("env"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if !st.Configured {
		s.writeErr(w, r, &service.Error{Status: http.StatusNotFound, Code: "ca_not_configured", Msg: "ca not installed"})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = io.WriteString(w, st.ChainPEM)
}

func (s *Server) crl(w http.ResponseWriter, r *http.Request) {
	der, err := s.svc.CRL(r.Context(), r.PathValue("env"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(der)
}

func (s *Server) whoami(w http.ResponseWriter, _ *http.Request, p *auth.Principal, _ []byte) {
	writeJSON(w, http.StatusOK, model.WhoAmI{ARN: p.ARN, Principal: p.Name(), Account: p.Account, Permissions: p.Permissions,
		Environments: s.svc.Access(p)})
}

func (s *Server) caCSR(w http.ResponseWriter, r *http.Request, p *auth.Principal, body []byte) {
	var req model.CACSRRequest
	if err := decode(body, &req); err != nil {
		s.writeErr(w, r, err)
		return
	}
	out, err := s.svc.CACSR(r.Context(), p, r.PathValue("env"), req)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) caInstall(w http.ResponseWriter, r *http.Request, p *auth.Principal, body []byte) {
	var req model.CAInstallRequest
	if err := decode(body, &req); err != nil {
		s.writeErr(w, r, err)
		return
	}
	out, err := s.svc.CAInstall(r.Context(), p, r.PathValue("env"), req)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) issue(w http.ResponseWriter, r *http.Request, p *auth.Principal, body []byte) {
	var req model.IssueRequest
	if err := decode(body, &req); err != nil {
		s.writeErr(w, r, err)
		return
	}
	out, err := s.svc.Issue(r.Context(), p, req)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request, p *auth.Principal, _ []byte) {
	out, err := s.svc.ListDevices(r.Context(), p, r.URL.Query().Get("env"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request, p *auth.Principal, _ []byte) {
	out, err := s.svc.GetDevice(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) bundle(w http.ResponseWriter, r *http.Request, p *auth.Principal, _ []byte) {
	q := r.URL.Query()
	includeKey := q.Get("include_key") == "true" || q.Get("include_key") == "1"
	out, err := s.svc.Bundle(r.Context(), p, r.PathValue("id"), q.Get("serial"), includeKey)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) provisioned(w http.ResponseWriter, r *http.Request, p *auth.Principal, body []byte) {
	var req model.ProvisionRequest
	if err := decode(body, &req); err != nil {
		s.writeErr(w, r, err)
		return
	}
	out, err := s.svc.MarkProvisioned(r.Context(), p, r.PathValue("id"), req)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, p *auth.Principal, body []byte) {
	var req model.RevokeRequest
	if err := decode(body, &req); err != nil {
		s.writeErr(w, r, err)
		return
	}
	out, err := s.svc.Revoke(r.Context(), p, r.PathValue("id"), req)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) importCert(w http.ResponseWriter, r *http.Request, p *auth.Principal, body []byte) {
	var req model.ImportRequest
	if err := decode(body, &req); err != nil {
		s.writeErr(w, r, err)
		return
	}
	out, err := s.svc.Import(r.Context(), p, req)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request, p *auth.Principal, _ []byte) {
	day := time.Now().UTC()
	if d := r.URL.Query().Get("day"); d != "" {
		t, err := time.Parse("2006-01-02", d)
		if err != nil {
			s.writeErr(w, r, &service.Error{Status: http.StatusBadRequest, Code: "bad_request", Msg: "day must be YYYY-MM-DD"})
			return
		}
		day = t
	}
	out, err := s.svc.Audit(r.Context(), p, day)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
