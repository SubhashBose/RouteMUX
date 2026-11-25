package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// SocketPerm holds the ownership and mode to apply to a Unix domain socket
// after it is created. Each part is optional: a zero Mode means "leave the
// mode as created" (the process umask decides), and an empty UID/GID means
// "leave that ownership component unchanged".
type SocketPerm struct {
	Mode    os.FileMode // 0 = not specified
	HasMode bool
	UID     int // -1 = not specified
	GID     int // -1 = not specified

	raw string // original spec, for error messages and reload comparison
}

// parseSocketPerm parses a "mode[:user[:group]]" specification where every
// part is optional. Accepted forms include:
//
//	0660               mode only
//	660                mode only (leading zero optional)
//	0660:www-data      mode and user (group unchanged)
//	0660:www-data:www  mode, user and group
//	0660::www-data     mode and group, user unchanged
//	:www-data          user only
//	::www-data         group only
//	:www-data:www      user and group, mode unchanged
//
// User and group may be given as names or numeric IDs. An empty spec returns
// a zero-value SocketPerm meaning "apply nothing".
func parseSocketPerm(spec string) (*SocketPerm, error) {
	sp := &SocketPerm{UID: -1, GID: -1, raw: spec}
	if strings.TrimSpace(spec) == "" {
		return sp, nil
	}

	parts := strings.Split(spec, ":")
	if len(parts) > 3 {
		return nil, fmt.Errorf("socket-perm %q: expected at most mode:user:group", spec)
	}

	// --- mode ---
	if m := strings.TrimSpace(parts[0]); m != "" {
		// Always base 8 — "660" and "0660" mean the same thing, and a decimal
		// reading of a permission string is never what the user intended.
		v, err := strconv.ParseUint(m, 8, 32)
		if err != nil {
			return nil, fmt.Errorf("socket-perm %q: invalid mode %q (expected octal, e.g. 660 or 0660)", spec, m)
		}
		if v > 0o7777 {
			return nil, fmt.Errorf("socket-perm %q: mode %q out of range", spec, m)
		}
		sp.Mode = os.FileMode(v)
		sp.HasMode = true
	}

	// --- user ---
	if len(parts) > 1 {
		if u := strings.TrimSpace(parts[1]); u != "" {
			uid, err := lookupUID(u)
			if err != nil {
				return nil, fmt.Errorf("socket-perm %q: %w", spec, err)
			}
			sp.UID = uid
		}
	}

	// --- group ---
	if len(parts) > 2 {
		if g := strings.TrimSpace(parts[2]); g != "" {
			gid, err := lookupGID(g)
			if err != nil {
				return nil, fmt.Errorf("socket-perm %q: %w", spec, err)
			}
			sp.GID = gid
		}
	}

	return sp, nil
}

// lookupUID resolves a user name or numeric uid to a numeric uid.
func lookupUID(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return 0, fmt.Errorf("unknown user %q: %w", s, err)
	}
	n, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, fmt.Errorf("user %q has non-numeric uid %q", s, u.Uid)
	}
	return n, nil
}

// lookupGID resolves a group name or numeric gid to a numeric gid.
func lookupGID(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return 0, fmt.Errorf("unknown group %q: %w", s, err)
	}
	n, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("group %q has non-numeric gid %q", s, g.Gid)
	}
	return n, nil
}

// isSet reports whether the spec asks for any change at all.
func (sp *SocketPerm) isSet() bool {
	return sp != nil && (sp.HasMode || sp.UID >= 0 || sp.GID >= 0)
}

// apply sets ownership and mode on the socket file. Ownership is changed
// before the mode so the socket is never briefly group-accessible to the wrong
// group. Any error is returned so the caller can fail startup loudly rather
// than serve on a socket with unintended permissions.
func (sp *SocketPerm) apply(path string) error {
	if !sp.isSet() {
		return nil
	}
	if sp.UID >= 0 || sp.GID >= 0 {
		// -1 means "leave unchanged" for os.Chown, which matches our sentinel.
		if err := os.Chown(path, sp.UID, sp.GID); err != nil {
			return fmt.Errorf("socket-perm: chown %s: %w", path, err)
		}
	}
	if sp.HasMode {
		if err := os.Chmod(path, sp.Mode); err != nil {
			return fmt.Errorf("socket-perm: chmod %s: %w", path, err)
		}
	}
	return nil
}

// String renders the effective settings for logging.
func (sp *SocketPerm) String() string {
	if !sp.isSet() {
		return ""
	}
	var b strings.Builder
	if sp.HasMode {
		fmt.Fprintf(&b, "mode %04o", sp.Mode)
	}
	if sp.UID >= 0 {
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "uid %d", sp.UID)
	}
	if sp.GID >= 0 {
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "gid %d", sp.GID)
	}
	return b.String()
}

// socketPermSpec returns the raw spec string for comparison across reloads,
// treating nil as "unset".
func socketPermSpec(sp *SocketPerm) string {
	if sp == nil {
		return ""
	}
	return sp.raw
}
