package handlers

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCredentialCacheGetPut(t *testing.T) {
	c := newCredentialCache(time.Minute, 8)
	key := credCacheKey("alice", "secret")
	apID := uuid.New()
	userID := uuid.New()

	if _, ok := c.get(key); ok {
		t.Fatal("expected miss on empty cache")
	}

	c.put(key, apID, userID)

	entry, ok := c.get(key)
	if !ok {
		t.Fatal("expected hit after put")
	}
	if entry.appPasswordID != apID || entry.userID != userID {
		t.Fatalf("entry = %#v, want app password %s user %s", entry, apID, userID)
	}
}

func TestCredCacheKeyDistinctAndOpaque(t *testing.T) {
	if credCacheKey("alice", "secret") == credCacheKey("alice", "secre7") {
		t.Fatal("different passwords must produce different keys")
	}
	if credCacheKey("alice", "secret") == credCacheKey("alic3", "secret") {
		t.Fatal("different usernames must produce different keys")
	}
	// A username ending in ":" must not collide with a different split point.
	if credCacheKey("a", "b:c") == credCacheKey("a:b", "c") {
		t.Fatal("username/password boundary should not be ambiguous for these inputs")
	}
	if strings.Contains(credCacheKey("alice", "supersecret"), "supersecret") {
		t.Fatal("cache key must not embed the plaintext password")
	}
}

func TestCredentialCacheExpiry(t *testing.T) {
	c := newCredentialCache(time.Minute, 8)
	key := credCacheKey("alice", "secret")

	c.entries[key] = credCacheEntry{
		appPasswordID: uuid.New(),
		userID:        uuid.New(),
		expiresAt:     time.Now().Add(-time.Second),
	}

	if _, ok := c.get(key); ok {
		t.Fatal("expired entry must not be returned")
	}
	if _, ok := c.entries[key]; ok {
		t.Fatal("expired entry should be deleted on access")
	}
}

func TestCredentialCacheInvalidateAppPassword(t *testing.T) {
	c := newCredentialCache(time.Minute, 8)
	revokedAP := uuid.New()
	otherAP := uuid.New()
	userID := uuid.New()

	keyA := credCacheKey("alice", "secret")
	keyB := credCacheKey("bob", "other")
	c.put(keyA, revokedAP, userID)
	c.put(keyB, otherAP, userID)

	c.invalidateAppPassword(revokedAP)

	if _, ok := c.get(keyA); ok {
		t.Fatal("entry for the revoked app password must be removed")
	}
	if _, ok := c.get(keyB); !ok {
		t.Fatal("entries for other app passwords must remain")
	}
}

func TestCredentialCacheSweepExpired(t *testing.T) {
	c := newCredentialCache(time.Minute, 8)
	live := credCacheKey("alice", "secret")
	dead := credCacheKey("bob", "other")

	c.put(live, uuid.New(), uuid.New())
	c.entries[dead] = credCacheEntry{
		appPasswordID: uuid.New(),
		userID:        uuid.New(),
		expiresAt:     time.Now().Add(-time.Minute),
	}

	c.sweepExpired()

	if _, ok := c.entries[dead]; ok {
		t.Fatal("sweepExpired should remove expired entries")
	}
	if _, ok := c.entries[live]; !ok {
		t.Fatal("sweepExpired should keep live entries")
	}
}

func TestCredentialCacheBoundsSize(t *testing.T) {
	const max = 4
	c := newCredentialCache(time.Minute, max)

	for i := 0; i < 50; i++ {
		c.put(credCacheKey("user", fmt.Sprintf("pw-%d", i)), uuid.New(), uuid.New())
	}

	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()

	if n > max {
		t.Fatalf("cache size = %d, want <= %d", n, max)
	}
}
