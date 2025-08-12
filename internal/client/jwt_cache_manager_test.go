package client

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
)

func TestNewJWTCacheManager(t *testing.T) {
	logger := hclog.NewNullLogger()
	jcm := newJWTCacheManager(logger)

	if jcm == nil {
		t.Fatal("Expected non-nil JWT cache manager")
	}
	if jcm.logger == nil {
		t.Error("Logger should be set")
	}
	if jcm.cache == nil {
		t.Error("Cache should be initialized")
	}
}

func TestJWTCacheManager_Get(t *testing.T) {
	tests := []struct {
		name        string
		spiffeID    string
		audiences   []string
		setupCache  func(*jwtCacheManager)
		expectToken string
		expectFound bool
	}{
		{
			name:        "cache miss - not found",
			spiffeID:    "spiffe://example.org/test",
			audiences:   []string{"audience1"},
			setupCache:  func(jcm *jwtCacheManager) {},
			expectToken: "",
			expectFound: false,
		},
		{
			name:      "cache hit - valid token",
			spiffeID:  "spiffe://example.org/test",
			audiences: []string{"audience1"},
			setupCache: func(jcm *jwtCacheManager) {
				key := jcm.createCacheKey("spiffe://example.org/test", []string{"audience1"})
				jcm.cache[key] = &jwtCacheEntry{
					token:     "valid-token",
					expiresAt: time.Now().Add(2 * time.Hour),
					audiences: []string{"audience1"},
				}
			},
			expectToken: "valid-token",
			expectFound: true,
		},
		{
			name:      "cache miss - expired token",
			spiffeID:  "spiffe://example.org/test",
			audiences: []string{"audience1"},
			setupCache: func(jcm *jwtCacheManager) {
				key := jcm.createCacheKey("spiffe://example.org/test", []string{"audience1"})
				jcm.cache[key] = &jwtCacheEntry{
					token:     "expired-token",
					expiresAt: time.Now().Add(-1 * time.Hour),
					audiences: []string{"audience1"},
				}
			},
			expectToken: "",
			expectFound: false,
		},
		{
			name:      "cache miss - needs refresh",
			spiffeID:  "spiffe://example.org/test",
			audiences: []string{"audience1"},
			setupCache: func(jcm *jwtCacheManager) {
				key := jcm.createCacheKey("spiffe://example.org/test", []string{"audience1"})
				jcm.cache[key] = &jwtCacheEntry{
					token: "needs-refresh",
					// Less than refresh buffer
					expiresAt: time.Now().Add(30 * time.Minute),
					audiences: []string{"audience1"},
				}
			},
			expectToken: "",
			expectFound: false,
		},
		{
			name:      "cache hit - multiple audiences",
			spiffeID:  "spiffe://example.org/test",
			audiences: []string{"aud1", "aud2", "aud3"},
			setupCache: func(jcm *jwtCacheManager) {
				key := jcm.createCacheKey("spiffe://example.org/test", []string{"aud1", "aud2", "aud3"})
				jcm.cache[key] = &jwtCacheEntry{
					token:     "multi-aud-token",
					expiresAt: time.Now().Add(2 * time.Hour),
					audiences: []string{"aud1", "aud2", "aud3"},
				}
			},
			expectToken: "multi-aud-token",
			expectFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			jcm := newJWTCacheManager(logger)

			tt.setupCache(jcm)

			token := jcm.get(tt.spiffeID, tt.audiences)

			if token != tt.expectToken {
				t.Errorf("Expected token %q, got %q", tt.expectToken, token)
			}
		})
	}
}

func TestJWTCacheManager_Put(t *testing.T) {
	logger := hclog.NewNullLogger()
	jcm := newJWTCacheManager(logger)

	spiffeID := "spiffe://example.org/test"
	audiences := []string{"audience1", "audience2"}
	token := "test-token"
	expiresAt := time.Now().Add(2 * time.Hour)

	jcm.put(spiffeID, audiences, token, expiresAt)

	// Verify it was stored
	key := jcm.createCacheKey(spiffeID, audiences)
	entry, exists := jcm.cache[key]
	if !exists {
		t.Fatal("Token was not stored in cache")
	}
	if entry.token != token {
		t.Errorf("Expected token %q, got %q", token, entry.token)
	}
	if !entry.expiresAt.Equal(expiresAt) {
		t.Errorf("Expected expiry %v, got %v", expiresAt, entry.expiresAt)
	}

	// Verify we can retrieve it
	retrievedToken := jcm.get(spiffeID, audiences)
	if retrievedToken != token {
		t.Errorf("Retrieved token %q does not match stored token %q", retrievedToken, token)
	}
}

func TestJWTCacheManager_CreateCacheKey(t *testing.T) {
	tests := []struct {
		name      string
		spiffeID  string
		audiences []string
		expected  string
	}{
		{
			name:      "single audience",
			spiffeID:  "spiffe://example.org/test",
			audiences: []string{"audience1"},
			expected:  "spiffe://example.org/test:audience1",
		},
		{
			name:      "multiple audiences sorted",
			spiffeID:  "spiffe://example.org/test",
			audiences: []string{"zebra", "alpha", "beta"},
			expected:  "spiffe://example.org/test:alpha,beta,zebra",
		},
		{
			name:      "empty audiences",
			spiffeID:  "spiffe://example.org/test",
			audiences: []string{},
			expected:  "spiffe://example.org/test:",
		},
		{
			name:      "audiences already sorted",
			spiffeID:  "spiffe://example.org/test",
			audiences: []string{"a", "b", "c"},
			expected:  "spiffe://example.org/test:a,b,c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			jcm := newJWTCacheManager(logger)

			key := jcm.createCacheKey(tt.spiffeID, tt.audiences)

			if key != tt.expected {
				t.Errorf("Expected key %q, got %q", tt.expected, key)
			}
		})
	}
}

func TestJWTCacheManager_CreateCacheKey_Deterministic(t *testing.T) {
	logger := hclog.NewNullLogger()
	jcm := newJWTCacheManager(logger)

	spiffeID := "spiffe://example.org/test"
	audiences1 := []string{"z", "a", "m"}
	audiences2 := []string{"m", "z", "a"}

	key1 := jcm.createCacheKey(spiffeID, audiences1)
	key2 := jcm.createCacheKey(spiffeID, audiences2)

	if key1 != key2 {
		t.Errorf("Keys should be identical for same audiences in different order: %q != %q", key1, key2)
	}
}

func TestJWTCacheManager_Size(t *testing.T) {
	logger := hclog.NewNullLogger()
	jcm := newJWTCacheManager(logger)

	if jcm.size() != 0 {
		t.Errorf("Expected size 0, got %d", jcm.size())
	}

	// Add some entries
	jcm.put("spiffe://example.org/test1", []string{"aud1"}, "token1", time.Now().Add(1*time.Hour))
	if jcm.size() != 1 {
		t.Errorf("Expected size 1, got %d", jcm.size())
	}

	jcm.put("spiffe://example.org/test2", []string{"aud2"}, "token2", time.Now().Add(1*time.Hour))
	if jcm.size() != 2 {
		t.Errorf("Expected size 2, got %d", jcm.size())
	}
}

func TestJWTCacheManager_Clear(t *testing.T) {
	logger := hclog.NewNullLogger()
	jcm := newJWTCacheManager(logger)

	jcm.put("spiffe://example.org/test1", []string{"aud1"}, "token1", time.Now().Add(1*time.Hour))
	jcm.put("spiffe://example.org/test2", []string{"aud2"}, "token2", time.Now().Add(1*time.Hour))

	if jcm.size() != 2 {
		t.Errorf("Expected size 2 before clear, got %d", jcm.size())
	}

	jcm.clear()

	if jcm.size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", jcm.size())
	}

	token := jcm.get("spiffe://example.org/test1", []string{"aud1"})
	if token != "" {
		t.Error("Expected empty token after clear")
	}
}

func TestJWTCacheManager_ConcurrentAccess(t *testing.T) {
	logger := hclog.NewNullLogger()
	jcm := newJWTCacheManager(logger)

	done := make(chan bool, 100)

	// Concurrent puts
	for i := 0; i < 50; i++ {
		go func(id int) {
			spiffeID := fmt.Sprintf("spiffe://example.org/test%d", id)
			audiences := []string{fmt.Sprintf("aud%d", id)}
			token := fmt.Sprintf("token%d", id)
			jcm.put(spiffeID, audiences, token, time.Now().Add(1*time.Hour))
			done <- true
		}(i)
	}

	// Concurrent gets
	for i := 0; i < 50; i++ {
		go func(id int) {
			spiffeID := fmt.Sprintf("spiffe://example.org/test%d", id)
			audiences := []string{fmt.Sprintf("aud%d", id)}
			jcm.get(spiffeID, audiences)
			done <- true
		}(i)
	}

	// Wait for all operations
	for i := 0; i < 100; i++ {
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}
}
