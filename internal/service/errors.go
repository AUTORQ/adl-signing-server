package service

import (
	"context"
	"fmt"
	"net/http"
)

// Error is returned for anything the caller can act on. The API layer turns
// it into a JSON error with the same status and code.
type Error struct {
	Status  int
	Code    string
	Msg     string
	Details map[string]string
}

func (e *Error) Error() string { return e.Msg }

func badRequest(format string, args ...any) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "bad_request", Msg: fmt.Sprintf(format, args...)}
}

func forbidden(perm string) *Error {
	return &Error{Status: http.StatusForbidden, Code: "forbidden", Msg: "missing permission " + perm, Details: map[string]string{"permission": perm}}
}

func notFound(format string, args ...any) *Error {
	return &Error{Status: http.StatusNotFound, Code: "not_found", Msg: fmt.Sprintf(format, args...)}
}

func conflict(code string, details map[string]string, format string, args ...any) *Error {
	return &Error{Status: http.StatusConflict, Code: code, Msg: fmt.Sprintf(format, args...), Details: details}
}

func unavailable(code string, format string, args ...any) *Error {
	return &Error{Status: http.StatusServiceUnavailable, Code: code, Msg: fmt.Sprintf(format, args...)}
}

type requestIDKey struct{}

// WithRequestID tags ctx so audit events can be tied back to access logs.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}
