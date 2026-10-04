// Package lambdahttp runs an http.Handler behind API Gateway HTTP APIs
// (payload format 2.0), so the Lambda deployment serves exactly the same
// handler as the EC2 one.
package lambdahttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

// Handler adapts h into a Lambda handler function.
func Handler(h http.Handler) func(context.Context, events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return func(ctx context.Context, ev events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
		req, err := toRequest(ctx, ev)
		if err != nil {
			return events.APIGatewayV2HTTPResponse{StatusCode: http.StatusBadRequest, Body: `{"error":"bad request","code":"bad_request"}`,
				Headers: map[string]string{"Content-Type": "application/json"}}, nil
		}
		rw := newResponseWriter()
		h.ServeHTTP(rw, req)
		return rw.toResponse(), nil
	}
}

func toRequest(ctx context.Context, ev events.APIGatewayV2HTTPRequest) (*http.Request, error) {
	var body []byte
	if ev.IsBase64Encoded {
		b, err := base64.StdEncoding.DecodeString(ev.Body)
		if err != nil {
			return nil, err
		}
		body = b
	} else {
		body = []byte(ev.Body)
	}
	u := &url.URL{Path: ev.RawPath, RawQuery: ev.RawQueryString}
	if p, err := url.PathUnescape(ev.RawPath); err == nil {
		u.Path = p
		u.RawPath = ev.RawPath
	}
	method := ev.RequestContext.HTTP.Method
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range ev.Headers {
		// API Gateway joins repeated headers with commas.
		req.Header.Set(k, v)
	}
	if len(ev.Cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(ev.Cookies, "; "))
	}
	// Use API Gateway's request id so our logs line up with its access log.
	if ev.RequestContext.RequestID != "" {
		req.Header.Set("X-Request-Id", ev.RequestContext.RequestID)
	}
	req.RemoteAddr = ev.RequestContext.HTTP.SourceIP
	req.Host = ev.RequestContext.DomainName
	req.RequestURI = u.RequestURI()
	return req, nil
}

type responseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newResponseWriter() *responseWriter {
	return &responseWriter{header: http.Header{}}
}

func (w *responseWriter) Header() http.Header { return w.header }

func (w *responseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(b)
}

func (w *responseWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}

func (w *responseWriter) toResponse() events.APIGatewayV2HTTPResponse {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	headers := map[string]string{}
	for k, v := range w.header {
		headers[k] = strings.Join(v, ", ")
	}
	resp := events.APIGatewayV2HTTPResponse{StatusCode: w.status, Headers: headers}
	ct := w.header.Get("Content-Type")
	if isText(ct) {
		resp.Body = w.body.String()
	} else {
		resp.Body = base64.StdEncoding.EncodeToString(w.body.Bytes())
		resp.IsBase64Encoded = true
	}
	return resp
}

func isText(ct string) bool {
	return ct == "" || strings.HasPrefix(ct, "text/") || strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "application/x-pem-file")
}
