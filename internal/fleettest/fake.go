// Package fleettest provides a fake Fleet Manager for tests. It mimics the
// login flow (csrftoken cookie + X-CSRFToken header, bearer tokens), token
// expiry, CSRF checks on non-GET requests and GraphQL error responses.
package fleettest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	Username = "claude"
	Password = "s3cret pass"
	CSRF     = "csrf-abc"
)

// Server is a fake Fleet Manager.
type Server struct {
	*httptest.Server
	PasswordFile string

	mu       sync.Mutex
	token    string
	Logins   int
	Logouts  int
	routes   map[string]any // "GET /path" -> JSON body
	LastGQL  string
	Requests []string
}

// New starts a fake Fleet Manager over TLS.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{routes: map[string]any{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	s.PasswordFile = filepath.Join(t.TempDir(), "pw.txt")
	if err := os.WriteFile(s.PasswordFile, []byte(Password+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

// Route registers a JSON response for "METHOD /path".
func (s *Server) Route(methodPath string, body any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[methodPath] = body
}

// RequestLog returns "METHOD /path" for every request so far.
func (s *Server) RequestLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Requests...)
}

// LoginCount is the number of successful logins.
func (s *Server) LoginCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Logins
}

// LogoutCount is the number of logouts.
func (s *Server) LogoutCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Logouts
}

// ExpireToken makes the current bearer token invalid.
func (s *Server) ExpireToken() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = "expired"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; schema=object")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Requests = append(s.Requests, r.Method+" "+r.URL.Path)

	if r.URL.Path == "/" {
		http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: CSRF, Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html></html>")
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		ck, err := r.Cookie("csrftoken")
		if err == nil && r.Header.Get("X-CSRFToken") != ck.Value {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "missing csrf token in request header"})
			return
		}
	}

	if r.URL.Path == "/fleet/v1/login" && r.Method == http.MethodPost {
		var body struct{ Username, Password string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Header.Get("X-CSRFToken") != CSRF || body.Username != Username || body.Password != Password {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "bad login"})
			return
		}
		s.Logins++
		s.token = fmt.Sprintf("token-%d", s.Logins)
		writeJSON(w, http.StatusOK, map[string]string{"token": s.token})
		return
	}

	if r.Header.Get("Authorization") != "Bearer "+s.token || s.token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "No authorization header was included in request"})
		return
	}

	switch {
	case r.URL.Path == "/fleet/v1/logout":
		s.Logouts++
		s.token = ""
		writeJSON(w, http.StatusOK, map[string]string{})
		return
	case r.URL.Path == "/graph/query":
		var body struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.LastGQL = body.Query
		if strings.Contains(body.Query, "invalidField") {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"errors": []any{map[string]any{"message": `Cannot query field "invalidField"`}}, "data": nil,
			})
			return
		}
		if v, ok := s.routes["GRAPHQL"]; ok {
			writeJSON(w, http.StatusOK, v)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"hello": map[string]any{"message": "hi"}}})
		return
	}

	if v, ok := s.routes[r.Method+" "+r.URL.Path]; ok {
		if b, isBytes := v.([]byte); isBytes {
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(b)
			return
		}
		writeJSON(w, http.StatusOK, v)
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
}
