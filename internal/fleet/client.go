// Package fleet is a client for the Corelight Fleet Manager REST and GraphQL APIs.
package fleet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	loginPath   = "/fleet/v1/login"
	logoutPath  = "/fleet/v1/logout"
	graphQLPath = "/graph/query"
	csrfCookie  = "csrftoken"
	csrfHeader  = "X-CSRFToken"
	maxBodySize = 64 << 20 // refuse to buffer more than 64 MiB from one response
)

// Options configures a Client.
type Options struct {
	// BaseURL is the Fleet Manager URL, for example https://fleet.example.com.
	BaseURL string
	// Username of a local Fleet Manager user without 2FA.
	Username string
	// PasswordFile holds the user's password. It is read at each login and
	// never kept in memory longer than the login request.
	PasswordFile string
	// CAFile is an optional PEM bundle added to the system roots.
	CAFile string
	// InsecureSkipVerify disables TLS certificate verification.
	InsecureSkipVerify bool
	// Timeout for each HTTP request. Zero means 60 seconds.
	Timeout time.Duration
	// UserAgent sent with every request.
	UserAgent string
	// Password is used when PasswordFile is empty (bootstrap only).
	Password string
	// PinSHA256 accepts exactly the server certificate with this SHA-256
	// fingerprint (hex, colons optional) instead of verifying a chain.
	PinSHA256 string
}

// Client talks to one Fleet Manager. It logs in on first use and logs in
// again when the bearer token is rejected. It is safe for concurrent use.
type Client struct {
	base         *url.URL
	username     string
	passwordFile string
	password     string
	userAgent    string
	http         *http.Client

	mu    sync.Mutex
	token string
	// mustChangePassword is the last login's require_password_change.
	mustChangePassword bool
}

// Response is a raw API response.
type Response struct {
	Status      int
	ContentType string
	Header      http.Header
	Body        []byte
	// Truncated is set by GetCapped when the body exceeded its limit; Body
	// is then empty.
	Truncated bool
}

// IsJSON reports whether the response body is JSON.
func (r *Response) IsJSON() bool {
	return strings.Contains(r.ContentType, "json")
}

// APIError is returned for non-2xx responses.
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// New returns a Client. It does not contact Fleet Manager.
func New(opts Options) (*Client, error) {
	base, err := ParseBaseURL(opts.BaseURL)
	if err != nil {
		return nil, err
	}
	if opts.Username == "" {
		return nil, errors.New("fleet: username is required")
	}
	if opts.PasswordFile == "" && opts.Password == "" {
		return nil, errors.New("fleet: password file is required")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.InsecureSkipVerify} //nolint:gosec // opt-in
	if opts.PinSHA256 != "" {
		pin, err := normalizeFingerprint(opts.PinSHA256)
		if err != nil {
			return nil, err
		}
		// Chain verification is replaced by an exact certificate match.
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // pinned below
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("fleet: server sent no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if got := hex.EncodeToString(sum[:]); got != pin {
				return fmt.Errorf("fleet: server certificate %s does not match the pinned %s", got, pin)
			}
			return nil
		}
	}
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("fleet: reading CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("fleet: no certificates found in %s", opts.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	ua := opts.UserAgent
	if ua == "" {
		ua = "fleet-mcp"
	}
	return &Client{
		base:         base,
		username:     opts.Username,
		passwordFile: opts.PasswordFile,
		password:     opts.Password,
		userAgent:    ua,
		http:         &http.Client{Transport: transport, Jar: jar, Timeout: timeout},
	}, nil
}

// ParseBaseURL accepts "host", "host:port" or "https://host[:port]".
func ParseBaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("fleet: base URL is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("fleet: bad base URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("fleet: base URL must use https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("fleet: base URL has no host")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""
	return u, nil
}

// Host returns the Fleet Manager host name.
func (c *Client) Host() string { return c.base.Host }

// normalizeFingerprint returns a SHA-256 fingerprint as lowercase hex
// without separators.
func normalizeFingerprint(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.LastIndex(s, "="); i >= 0 { // "sha256 Fingerprint=AB:CD..."
		s = s[i+1:]
	}
	s = strings.NewReplacer(":", "", " ", "").Replace(s)
	if b, err := hex.DecodeString(s); err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("fleet: bad SHA-256 fingerprint %q", s)
	}
	return s, nil
}

// NormalizeFingerprint is normalizeFingerprint for other packages.
func NormalizeFingerprint(s string) (string, error) { return normalizeFingerprint(s) }

// RequirePasswordChange reports whether the last login said the user must
// change their password.
func (c *Client) RequirePasswordChange() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mustChangePassword
}

func (c *Client) readPassword() (string, error) {
	if c.passwordFile == "" {
		return c.password, nil
	}
	b, err := os.ReadFile(c.passwordFile)
	if err != nil {
		return "", fmt.Errorf("fleet: reading password file: %w", err)
	}
	pw := strings.TrimRight(string(b), "\r\n")
	pw = strings.TrimPrefix(pw, string(rune(0xFEFF))) // tolerate a UTF-8 BOM
	if pw == "" {
		return "", errors.New("fleet: password file is empty")
	}
	return pw, nil
}

// Login obtains a new bearer token.
func (c *Client) Login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loginLocked(ctx)
}

func (c *Client) loginLocked(ctx context.Context) error {
	c.token = ""
	// Fleet Manager issues a csrftoken cookie on a plain page load and
	// requires it echoed back as X-CSRFToken on login.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/", nil), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fleet: fetching CSRF token: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	csrf := c.csrfToken()
	if csrf == "" {
		return errors.New("fleet: no csrftoken cookie from Fleet Manager")
	}

	pw, err := c.readPassword()
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"username": c.username, "password": pw})
	pw = ""
	if err != nil {
		return err
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.url(loginPath, nil), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set(csrfHeader, csrf)
	resp, err = c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fleet: login: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return &APIError{Method: http.MethodPost, Path: loginPath, Status: resp.StatusCode, Body: excerpt(rb)}
	}
	var lr struct {
		Token                 string `json:"token"`
		RequirePasswordChange bool   `json:"require_password_change"`
	}
	if err := json.Unmarshal(rb, &lr); err != nil || lr.Token == "" {
		return errors.New("fleet: login response had no token")
	}
	c.token = lr.Token
	c.mustChangePassword = lr.RequirePasswordChange
	return nil
}

func (c *Client) csrfToken() string {
	for _, ck := range c.http.Jar.Cookies(c.base) {
		if ck.Name == csrfCookie {
			return ck.Value
		}
	}
	return ""
}

// Logout ends the session, if there is one.
func (c *Client) Logout(ctx context.Context) error {
	c.mu.Lock()
	tok := c.token
	c.token = ""
	c.mu.Unlock()
	if tok == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(logoutPath, nil), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", c.userAgent)
	if csrf := c.csrfToken(); csrf != "" {
		req.Header.Set(csrfHeader, csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Method: http.MethodPost, Path: logoutPath, Status: resp.StatusCode}
	}
	return nil
}

func (c *Client) currentToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" {
		if err := c.loginLocked(ctx); err != nil {
			return "", err
		}
	}
	return c.token, nil
}

// relogin replaces the token if it is still the rejected one.
func (c *Client) relogin(ctx context.Context, rejected string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.token != rejected {
		return c.token, nil
	}
	if err := c.loginLocked(ctx); err != nil {
		return "", err
	}
	return c.token, nil
}

// ValidatePath checks that path is an absolute API path on this host.
func ValidatePath(path string) error {
	switch {
	case path == "" || path[0] != '/':
		return fmt.Errorf("path must start with /: %q", path)
	case strings.HasPrefix(path, "//"), strings.Contains(path, "://"):
		return fmt.Errorf("path must not name another host: %q", path)
	case strings.ContainsAny(path, "?#"):
		return fmt.Errorf("pass query parameters separately, not in the path: %q", path)
	case strings.Contains(path, ".."):
		return fmt.Errorf("path must not contain '..': %q", path)
	}
	return nil
}

func (c *Client) url(path string, query url.Values) string {
	u := *c.base
	u.Path = c.base.Path + path
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

// Do sends an authenticated request. Non-2xx responses return *APIError
// along with the response.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body []byte, contentType string) (*Response, error) {
	return c.do(ctx, method, path, query, body, contentType, maxBodySize, false)
}

// GetCapped is Get that stops reading after limit bytes. An oversized body
// sets Response.Truncated instead of returning an error, so callers can
// describe large downloads without buffering them.
func (c *Client) GetCapped(ctx context.Context, path string, query url.Values, limit int64) (*Response, error) {
	return c.do(ctx, http.MethodGet, path, query, nil, "", limit, true)
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body []byte, contentType string, limit int64, capped bool) (*Response, error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}
	tok, err := c.currentToken(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.send(ctx, tok, method, path, query, body, contentType, limit, capped)
	if err == nil && resp.Status == http.StatusUnauthorized {
		if tok, err = c.relogin(ctx, tok); err != nil {
			return nil, err
		}
		resp, err = c.send(ctx, tok, method, path, query, body, contentType, limit, capped)
	}
	if err != nil {
		return nil, err
	}
	if resp.Status < 200 || resp.Status > 299 {
		return resp, &APIError{Method: method, Path: path, Status: resp.Status, Body: excerpt(resp.Body)}
	}
	return resp, nil
}

// roundTrip sends one authenticated request; the caller closes the body.
func (c *Client) roundTrip(ctx context.Context, tok, method, path string, query url.Values, body []byte, contentType string) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path, query), rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	// The csrftoken cookie from login rides along in the jar; Fleet Manager
	// then requires the same value in X-CSRFToken on state-changing methods
	// and on GraphQL.
	if method != http.MethodGet && method != http.MethodHead {
		if csrf := c.csrfToken(); csrf != "" {
			req.Header.Set(csrfHeader, csrf)
		}
	}
	if body != nil && contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	return resp, nil
}

// Download streams the body of a GET to w without buffering it, for files
// larger than Do accepts. It fails if the body exceeds limit bytes.
func (c *Client) Download(ctx context.Context, path string, w io.Writer, limit int64) (int64, error) {
	if err := ValidatePath(path); err != nil {
		return 0, err
	}
	tok, err := c.currentToken(ctx)
	if err != nil {
		return 0, err
	}
	resp, err := c.roundTrip(ctx, tok, http.MethodGet, path, nil, nil, "")
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if tok, err = c.relogin(ctx, tok); err != nil {
			return 0, err
		}
		resp, err = c.roundTrip(ctx, tok, http.MethodGet, path, nil, nil, "")
	}
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, &APIError{Method: http.MethodGet, Path: path, Status: resp.StatusCode, Body: excerpt(b)}
	}
	if resp.ContentLength > limit {
		return 0, fmt.Errorf("GET %s: file is %d bytes, larger than the %d byte limit", path, resp.ContentLength, limit)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return n, fmt.Errorf("GET %s: %w", path, err)
	}
	if n > limit {
		return n, fmt.Errorf("GET %s: file is larger than the %d byte limit", path, limit)
	}
	return n, nil
}

func (c *Client) send(ctx context.Context, tok, method, path string, query url.Values, body []byte, contentType string, limit int64, capped bool) (*Response, error) {
	resp, err := c.roundTrip(ctx, tok, method, path, query, body, contentType)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := &Response{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Header: resp.Header}
	// Don't start reading a body that is known to be too large.
	if capped && resp.ContentLength > limit {
		out.Truncated = true
		return out, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s %s: reading body: %w", method, path, err)
	}
	if int64(len(b)) > limit {
		if capped {
			out.Truncated = true
			return out, nil
		}
		return nil, fmt.Errorf("%s %s: response larger than %d bytes", method, path, limit)
	}
	out.Body = b
	return out, nil
}

// Get sends an authenticated GET.
func (c *Client) Get(ctx context.Context, path string, query url.Values) (*Response, error) {
	return c.Do(ctx, http.MethodGet, path, query, nil, "")
}

// GetJSON sends a GET and decodes the JSON body into out.
func (c *Client) GetJSON(ctx context.Context, path string, query url.Values, out any) error {
	resp, err := c.Get(ctx, path, query)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return fmt.Errorf("GET %s: decoding JSON: %w", path, err)
	}
	return nil
}

// GraphQL posts a GraphQL document. GraphQL errors are returned in the
// response body, not as a Go error.
func (c *Client) GraphQL(ctx context.Context, query string, variables map[string]any) (*Response, error) {
	payload := map[string]any{"query": query}
	if len(variables) > 0 {
		payload["variables"] = variables
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(ctx, http.MethodPost, graphQLPath, nil, body, "application/json")
	// Validation failures arrive as HTTP 4xx (e.g. 422) with a normal
	// GraphQL {"errors": [...]} body; hand those back as a response.
	var apiErr *APIError
	if errors.As(err, &apiErr) && resp != nil && apiErr.Status >= 400 && apiErr.Status < 500 && hasGraphQLErrors(resp.Body) {
		return resp, nil
	}
	return resp, err
}

func hasGraphQLErrors(b []byte) bool {
	var probe struct {
		Errors []json.RawMessage `json:"errors"`
	}
	return json.Unmarshal(b, &probe) == nil && len(probe.Errors) > 0
}

func excerpt(b []byte) string {
	const n = 500
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}
