package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Basic-auth validation runs bcrypt on every request, which is intentionally
// slow (~50-100ms). Sync clients send hundreds of identical requests, so we
// keep a small, short-lived cache of credentials we have already validated.
const (
	credentialCacheTTL        = 120 * time.Second
	credentialCacheMaxEntries = 4096
)

// credCacheEntry binds a validated (username:password) to the app password that
// matched it. last_used_at is intentionally NOT refreshed on cache hits; it is
// updated only when bcrypt actually runs (on a miss), which throttles the write
// to at most once per TTL window per credential.
type credCacheEntry struct {
	appPasswordID uuid.UUID
	userID        uuid.UUID
	expiresAt     time.Time
}

// credentialCache is a TTL-bounded, size-bounded, in-memory cache of
// successfully validated Basic-auth credentials. Entries are keyed by a sha256
// of "username:password" so the plaintext password is never held in memory.
// Only successful validations are stored, so wrong passwords always fall
// through to the bcrypt path and are rejected every time.
type credentialCache struct {
	ttl        time.Duration
	maxEntries int

	mu      sync.Mutex
	entries map[string]credCacheEntry
}

func newCredentialCache(ttl time.Duration, maxEntries int) *credentialCache {
	return &credentialCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		entries:    make(map[string]credCacheEntry),
	}
}

// credCacheKey derives the lookup key from the credentials. The plaintext
// password is never stored; only this hash is kept in memory. The username is
// length-prefixed so the username/password boundary is unambiguous: without it,
// user "a" with password "b:c" would hash identically to user "a:b" with
// password "c". Usernames in this system never contain ':', but the cache's
// correctness should not depend on that invariant.
func credCacheKey(username, password string) string {
	h := sha256.New()
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], uint64(len(username)))
	h.Write(prefix[:])
	h.Write([]byte(username))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// get returns the cached entry for key when present and not expired. Expired
// entries are dropped on access.
func (c *credentialCache) get(key string) (credCacheEntry, bool) {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return credCacheEntry{}, false
	}
	if now.After(entry.expiresAt) {
		delete(c.entries, key)
		return credCacheEntry{}, false
	}
	return entry, true
}

// put stores a validated credential binding, bounding the map size first.
func (c *credentialCache) put(key string, appPasswordID, userID uuid.UUID) {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxEntries {
		c.evictLocked(now)
	}

	c.entries[key] = credCacheEntry{
		appPasswordID: appPasswordID,
		userID:        userID,
		expiresAt:     now.Add(c.ttl),
	}
}

// evictLocked drops expired entries and, if the cache is still at capacity,
// clears it entirely. The short TTL means a full reset only costs a brief burst
// of bcrypt work, which keeps memory hard-bounded without an LRU. Callers must
// hold c.mu.
func (c *credentialCache) evictLocked(now time.Time) {
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) >= c.maxEntries {
		c.entries = make(map[string]credCacheEntry)
	}
}

// invalidateAppPassword removes any cached binding for the given app password
// so a revoked or remotely wiped credential stops authenticating immediately,
// rather than lingering until its TTL elapses.
func (c *credentialCache) invalidateAppPassword(id uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, e := range c.entries {
		if e.appPasswordID == id {
			delete(c.entries, k)
		}
	}
}

// sweepExpired removes all expired entries. Intended for periodic background
// calls so idle entries do not linger until the next put or get.
func (c *credentialCache) sweepExpired() {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
}

// StartCredentialCacheJanitor periodically evicts expired Basic-auth cache
// entries until ctx is cancelled. Run it in its own goroutine.
func (h *Handler) StartCredentialCacheJanitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.credCache.sweepExpired()
		}
	}
}
