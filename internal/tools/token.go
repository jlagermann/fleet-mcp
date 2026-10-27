package tools

import (
	"errors"
	"sync"
	"time"
)

// tokenTTL is how long a confirm_token from a preview stays usable.
const tokenTTL = 30 * time.Minute

// issued holds the confirm tokens previews handed out in this server
// process. A token is the hash of the request (and, for most tools, of
// the state the preview read), so the same request yields the same token;
// recording it makes each confirmation follow a fresh preview: a token
// works once, only within tokenTTL, and not after the server restarts.
var issued = struct {
	sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

// now is time.Now, replaceable in tests.
var now = time.Now

// issueToken records that a preview handed out token and returns it.
func issueToken(token string) string {
	issued.Lock()
	defer issued.Unlock()
	t := now()
	for k, at := range issued.at {
		if t.Sub(at) > tokenTTL {
			delete(issued.at, k)
		}
	}
	issued.at[token] = t
	return token
}

// redeemToken accepts token once, if a preview in this server process
// issued it within tokenTTL. Callers check first that it matches the
// request.
func redeemToken(token string) error {
	issued.Lock()
	defer issued.Unlock()
	at, ok := issued.at[token]
	delete(issued.at, token)
	if !ok || now().Sub(at) > tokenTTL {
		return errors.New("confirm_token is not from a preview in this session, was already used, or is older than 30 minutes; preview again and get the user's approval for that preview")
	}
	return nil
}
