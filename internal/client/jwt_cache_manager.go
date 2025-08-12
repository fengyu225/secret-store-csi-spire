package client

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
)

type jwtCacheEntry struct {
	token     string
	expiresAt time.Time
	audiences []string
}

type jwtCacheManager struct {
	logger hclog.Logger
	cache  map[string]*jwtCacheEntry
	mu     sync.RWMutex
}

func newJWTCacheManager(logger hclog.Logger) *jwtCacheManager {
	return &jwtCacheManager{
		logger: logger,
		cache:  make(map[string]*jwtCacheEntry),
	}
}

func (jcm *jwtCacheManager) get(spiffeID string, audiences []string) string {
	key := jcm.createCacheKey(spiffeID, audiences)

	jcm.mu.RLock()
	defer jcm.mu.RUnlock()

	entry, exists := jcm.cache[key]
	if !exists {
		return ""
	}

	now := time.Now()
	if now.After(entry.expiresAt) {
		jcm.logger.Debug("JWT token expired in cache",
			"spiffe_id", spiffeID,
			"expired_at", entry.expiresAt,
		)
		return ""
	}

	// Check if needs refresh
	if now.Add(jwtRefreshBuffer).After(entry.expiresAt) {
		jcm.logger.Debug("JWT token needs refresh",
			"spiffe_id", spiffeID,
			"expires_at", entry.expiresAt,
		)
		return ""
	}

	return entry.token
}

func (jcm *jwtCacheManager) put(spiffeID string, audiences []string, token string, expiresAt time.Time) {
	key := jcm.createCacheKey(spiffeID, audiences)

	jcm.mu.Lock()
	defer jcm.mu.Unlock()

	jcm.cache[key] = &jwtCacheEntry{
		token:     token,
		expiresAt: expiresAt,
		audiences: audiences,
	}

	jcm.logger.Debug("JWT token cached",
		"spiffe_id", spiffeID,
		"audiences", audiences,
		"expires_at", expiresAt,
	)
}

func (jcm *jwtCacheManager) createCacheKey(spiffeID string, audiences []string) string {
	sortedAudiences := make([]string, len(audiences))
	copy(sortedAudiences, audiences)
	sort.Strings(sortedAudiences)
	return fmt.Sprintf("%s:%s", spiffeID, strings.Join(sortedAudiences, ","))
}

func (jcm *jwtCacheManager) size() int {
	jcm.mu.RLock()
	defer jcm.mu.RUnlock()
	return len(jcm.cache)
}

func (jcm *jwtCacheManager) clear() {
	jcm.mu.Lock()
	defer jcm.mu.Unlock()
	jcm.cache = make(map[string]*jwtCacheEntry)
}
