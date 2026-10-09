// Package audit appends a JSON Lines record for every change fleet-mcp
// makes to Fleet Manager.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record is one executed change.
type Record struct {
	Time     time.Time `json:"time"`
	Fleet    string    `json:"fleet"`
	User     string    `json:"user"`
	Tool     string    `json:"tool"`
	Method   string    `json:"method,omitempty"`
	Path     string    `json:"path,omitempty"`
	Query    string    `json:"query,omitempty"`
	Body     any       `json:"body,omitempty"` // redacted
	Token    string    `json:"confirm_token"`
	Status   int       `json:"status,omitempty"`
	Error    string    `json:"error,omitempty"`
	Response string    `json:"response,omitempty"` // redacted excerpt
}

// Log writes records to a file. A nil *Log discards records.
type Log struct {
	mu   sync.Mutex
	path string
}

// Open returns a Log appending to path, creating its directory.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	return &Log{path: path}, nil
}

// Path returns the log file path.
func (l *Log) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Write appends r. Errors are returned so callers can surface them; the
// change itself has already happened.
func (l *Log) Write(r Record) error {
	if l == nil {
		return nil
	}
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}
