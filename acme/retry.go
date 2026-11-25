package acme

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// Backoff bounds for failed issuance attempts. These protect the CA's rate
// limits: after a failure we wait at least minBackoff before retrying, doubling
// each consecutive failure up to maxBackoff. A successful issuance resets the
// state.
const (
	minIssueBackoff = 5 * time.Minute
	maxIssueBackoff = 24 * time.Hour
)

// issueState tracks issuance attempt history per vhost key, so the manager can
// avoid hammering the CA on repeated failures (which risks rate-limit lockout).
//
// The failure/backoff state is persisted to disk (when a path is set) so that a
// process restart — common with containers and process managers — does not
// reset the backoff and allow a crash-loop to burn through the CA's rate
// limits. This mirrors Caddy's guidance that in-memory rate state is reset on
// exit and is dangerous under supervisors.
type issueState struct {
	mu      sync.Mutex
	entries map[string]*issueEntry
	path    string // persistence file; empty disables persistence
}

type issueEntry struct {
	Failures     int       `json:"failures"`
	NextEligible time.Time `json:"next_eligible"`
}

func newIssueState() *issueState {
	return &issueState{entries: make(map[string]*issueEntry)}
}

// withPersistence sets the file path used to persist backoff state and loads
// any existing state from it. Errors loading are non-fatal (we start fresh).
func (s *issueState) withPersistence(path string) *issueState {
	s.path = path
	s.load()
	return s
}

// load reads persisted state from disk. Entries whose backoff window has
// elapsed are kept (they no longer block an attempt, see shouldAttempt) so the
// failure count survives a restart: otherwise a restarted process would drop
// back to the minimum backoff and retry a persistently failing domain far more
// often than intended. Only entries long past their window are discarded.
func (s *issueState) load() {
	if s.path == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return // no file yet, or unreadable — start fresh
	}
	var stored map[string]*issueEntry
	if err := json.Unmarshal(data, &stored); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, e := range stored {
		if e != nil && now.Before(e.NextEligible.Add(maxIssueBackoff)) {
			s.entries[k] = e
		}
	}
}

// save writes the current state to disk atomically. Caller must hold s.mu.
func (s *issueState) saveLocked() {
	if s.path == "" {
		return
	}
	data, err := json.Marshal(s.entries)
	if err != nil {
		return
	}
	// Best-effort: a failed save must not break issuance.
	_ = writeFileAtomic(s.path, data, 0o600)
}

// key identifies a vhost's certificate by its domain set.
func issueKey(domains []string) string {
	return strings.Join(domains, ",")
}

// shouldAttempt reports whether issuance for the given domains is allowed now.
// It returns false (and the remaining wait) while a backoff window is active.
func (s *issueState) shouldAttempt(domains []string) (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[issueKey(domains)]
	if e == nil {
		return true, 0
	}
	now := time.Now()
	if now.Before(e.NextEligible) {
		return false, e.NextEligible.Sub(now)
	}
	return true, 0
}

// recordAttempt marks an issuance attempt as started, before the CA is
// contacted: it moves the next eligible time at least minIssueBackoff ahead and
// persists it. If the process dies mid-attempt (crash, kill, watchdog or
// container restart), the restarted process still waits out that window rather
// than attempting again at once. The failure count is unchanged; the outcome
// is recorded by recordSuccess or recordFailure.
func (s *issueState) recordAttempt(domains []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := issueKey(domains)
	e := s.entries[k]
	if e == nil {
		e = &issueEntry{}
		s.entries[k] = e
	}
	if next := time.Now().Add(minIssueBackoff); next.After(e.NextEligible) {
		e.NextEligible = next
	}
	s.saveLocked()
}

// recordSuccess clears the failure state for the domains.
func (s *issueState) recordSuccess(domains []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, issueKey(domains))
	s.saveLocked()
}

// recordFailure increments the failure count and computes the next eligible
// retry time. If err is a CA rate-limit error carrying a Retry-After, that
// duration is honored exactly (it takes precedence over exponential backoff).
func (s *issueState) recordFailure(domains []string, err error) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := issueKey(domains)
	e := s.entries[k]
	if e == nil {
		e = &issueEntry{}
		s.entries[k] = e
	}
	e.Failures++

	// Honor the CA's Retry-After for rate-limit errors.
	if d, ok := rateLimitRetryAfter(err); ok && d > 0 {
		e.NextEligible = time.Now().Add(d)
		s.saveLocked()
		return d
	}

	// Exponential backoff: min * 2^(failures-1), capped at max.
	backoff := minIssueBackoff
	for i := 1; i < e.Failures && backoff < maxIssueBackoff; i++ {
		backoff *= 2
	}
	if backoff > maxIssueBackoff {
		backoff = maxIssueBackoff
	}
	e.NextEligible = time.Now().Add(backoff)
	s.saveLocked()
	return backoff
}

// rateLimitRetryAfter reports whether err is a CA rate-limit error, and its
// Retry-After. xacme.RateLimit only recognises an unwrapped *xacme.Error, while
// issuance errors arrive wrapped with context, so unwrap first.
func rateLimitRetryAfter(err error) (time.Duration, bool) {
	var ae *xacme.Error
	if !errors.As(err, &ae) {
		return 0, false
	}
	return xacme.RateLimit(ae)
}

// isTransientError reports whether err is a transport-level failure (network
// error, connection reset, request timeout) that never produced a CA verdict,
// so a single quick retry is harmless. ACME problem responses, failed
// validations and a whole attempt running out of time are not transient.
func isTransientError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var (
		ae *xacme.Error
		az *xacme.AuthorizationError
		oe *xacme.OrderError
	)
	if errors.As(err, &ae) || errors.As(err, &az) || errors.As(err, &oe) {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne)
}

// isPermanentError reports whether an ACME error is one that retrying cannot
// fix (policy/authorization problems), so we should not keep burning attempts.
func isPermanentError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, frag := range []string{
		"rejectedidentifier",
		"unsupportedidentifier",
		"policy",
		"malformed",
	} {
		if strings.Contains(msg, frag) {
			return true
		}
	}
	return false
}
