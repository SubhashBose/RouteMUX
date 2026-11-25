package acme

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
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
//
// Failures are handled in two classes:
//   - a CA verdict (failed validation, rejected order, rate limit, or anything
//     unrecognised) counts as a failure: exponential backoff, persisted.
//   - a failure that produced no verdict (network error, CA 5xx, local
//     pre-check) is not counted: the next attempt is minIssueBackoff later, or
//     after the CA's Retry-After if longer. Such failures do not use up the
//     CA's rate limits, so growing the backoff would only delay recovery.
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

// recordFailure records a failed attempt and returns the wait until the next
// one.
//
// A CA verdict increments the failure count and backs off exponentially; a
// rate-limit error's Retry-After is honored exactly instead. Both are
// persisted.
//
// A failure with no verdict (see isNoVerdictError) leaves the failure count
// alone: the next attempt is minIssueBackoff after this one ended. That is kept
// in memory only — the entry recordAttempt persisted before the attempt already
// limits a restarted process to waiting at most minIssueBackoff, while the
// in-memory time covers attempts that ran longer than minIssueBackoff (network
// timeouts). A CA Retry-After longer than minIssueBackoff (e.g. a 503 during
// maintenance) is honored and persisted.
func (s *issueState) recordFailure(domains []string, err error) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := issueKey(domains)
	e := s.entries[k]
	if e == nil {
		e = &issueEntry{}
		s.entries[k] = e
	}

	if isNoVerdictError(err) {
		if d, ok := retryAfter(err); ok && d > minIssueBackoff {
			e.NextEligible = time.Now().Add(d)
			s.saveLocked()
			return d
		}
		e.NextEligible = time.Now().Add(minIssueBackoff)
		return minIssueBackoff
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

// retryAfter returns the Retry-After of a CA error response, if it carried one
// (seconds or an HTTP date).
func retryAfter(err error) (time.Duration, bool) {
	var ae *xacme.Error
	if !errors.As(err, &ae) || ae.Header == nil {
		return 0, false
	}
	v := ae.Header.Get("Retry-After")
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d, true
		}
	}
	return 0, false
}

// errPrecheck marks issuance skipped by a local pre-check (domain does not
// resolve, certificate directory not writable) before the CA was contacted.
var errPrecheck = errors.New("skipping issuance")

// isNoVerdictError reports whether a failed attempt produced no verdict from
// the CA: a transport error, a CA server error (5xx), or a local pre-check.
// None of these count against the CA's rate limits. Everything else — ACME
// problems, failed validations, rate limits, an attempt running out of time,
// and unrecognised errors — is treated as a verdict, which errs on the safe
// side.
func isNoVerdictError(err error) bool {
	if errors.Is(err, errPrecheck) || isTransientError(err) {
		return true
	}
	var ae *xacme.Error
	return errors.As(err, &ae) && ae.StatusCode >= 500
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
