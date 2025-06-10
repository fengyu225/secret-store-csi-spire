package client

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	typesapi "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"spire-csi-provider/internal/metrics"
)

// ClientPool manages a pool of SPIRE clients for reuse across mount requests
type ClientPool struct {
	logger  hclog.Logger
	clients map[string]*poolEntry
	mu      sync.RWMutex

	staleTimeout    time.Duration
	cleanupInterval time.Duration

	cleanupCancel context.CancelFunc
}

type poolEntry struct {
	client       *Client
	key          string
	lastAccessed time.Time
	refCount     int
}

type PoolConfig struct {
	StaleTimeout    time.Duration
	CleanupInterval time.Duration
}

func NewClientPool(logger hclog.Logger, config PoolConfig) *ClientPool {
	if config.StaleTimeout <= 0 {
		config.StaleTimeout = 10 * time.Minute
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 1 * time.Minute
	}

	pool := &ClientPool{
		logger:          logger.Named("spire-client-pool"),
		clients:         make(map[string]*poolEntry),
		staleTimeout:    config.StaleTimeout,
		cleanupInterval: config.CleanupInterval,
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool.cleanupCancel = cancel
	go pool.cleanupRoutine(ctx)

	return pool
}

func (p *ClientPool) AcquireClient(ctx context.Context, config Config) (*Client, error) {
	key := p.buildClientKey(config)

	p.mu.RLock()
	entry, exists := p.clients[key]
	if exists {
		entry.lastAccessed = time.Now()
		entry.refCount++
		p.mu.RUnlock()

		p.logger.Debug("acquired existing SPIRE client from pool",
			"key", key,
			"pool_size", len(p.clients),
			"ref_count", entry.refCount,
		)

		metrics.RecordProviderPoolHit(config.SpiffeTrustDomain,
			extractNamespace(config.Selectors),
			extractServiceAccount(config.Selectors))

		return entry.client, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if entry, exists := p.clients[key]; exists {
		entry.lastAccessed = time.Now()
		entry.refCount++
		return entry.client, nil
	}

	p.logger.Info("creating new SPIRE client",
		"key", key,
		"socket_path", config.SpireSocketPath,
		"trust_domain", config.SpiffeTrustDomain,
		"pool_size", len(p.clients),
	)

	client, err := New(p.logger.Named("spire-client"), config)
	if err != nil {
		return nil, fmt.Errorf("failed to create SPIRE client: %w", err)
	}

	if err := client.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start SPIRE client: %w", err)
	}

	entry = &poolEntry{
		client:       client,
		key:          key,
		lastAccessed: time.Now(),
		refCount:     1,
	}
	p.clients[key] = entry

	metrics.RecordProviderPoolMiss(config.SpiffeTrustDomain,
		extractNamespace(config.Selectors),
		extractServiceAccount(config.Selectors))
	metrics.UpdateProviderPoolSize(config.SpiffeTrustDomain, len(p.clients))

	p.logger.Info("added new SPIRE client to pool",
		"key", key,
		"pool_size", len(p.clients),
	)

	return client, nil
}

func (p *ClientPool) ReleaseClient(config Config) {
	key := p.buildClientKey(config)

	p.mu.Lock()
	defer p.mu.Unlock()

	if entry, exists := p.clients[key]; exists {
		entry.refCount--
		if entry.refCount < 0 {
			entry.refCount = 0
		}

		p.logger.Debug("released SPIRE client",
			"key", key,
			"ref_count", entry.refCount,
		)
	}
}

// buildClientKey creates a unique key for client pooling
// Format: socketPath|trustDomain|selector1|selector2|...
func (p *ClientPool) buildClientKey(config Config) string {
	parts := []string{
		config.SpireSocketPath,
		config.SpiffeTrustDomain,
	}

	var selectorStrings []string
	for _, selector := range config.Selectors {
		selectorStrings = append(selectorStrings, fmt.Sprintf("%s:%s", selector.Type, selector.Value))
	}
	sort.Strings(selectorStrings)

	parts = append(parts, selectorStrings...)
	return strings.Join(parts, "|")
}

func (p *ClientPool) cleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(p.cleanupInterval)
	defer ticker.Stop()

	p.logger.Info("started client pool cleanup routine",
		"interval", p.cleanupInterval,
		"stale_timeout", p.staleTimeout,
	)

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("stopping client pool cleanup routine")
			return
		case <-ticker.C:
			p.performCleanup()
		}
	}
}

func (p *ClientPool) performCleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.clients) == 0 {
		return
	}

	now := time.Now()
	toRemove := []string{}

	for key, entry := range p.clients {
		// Only remove if refCount is 0 and it's stale
		if entry.refCount == 0 && now.Sub(entry.lastAccessed) > p.staleTimeout {
			toRemove = append(toRemove, key)
		}
	}

	removed := 0
	for _, key := range toRemove {
		if entry, exists := p.clients[key]; exists {
			p.logger.Info("removing stale client from pool",
				"key", key,
				"last_accessed", entry.lastAccessed,
				"age_minutes", int(now.Sub(entry.lastAccessed).Minutes()),
			)

			if err := entry.client.Stop(); err != nil {
				p.logger.Error("failed to stop stale client",
					"key", key,
					"error", err,
				)
			}

			delete(p.clients, key)
			removed++
			metrics.RecordProviderEviction("stale")
		}
	}

	if removed > 0 {
		p.logger.Info("client pool cleanup completed",
			"removed", removed,
			"remaining", len(p.clients),
		)

		for key := range p.clients {
			parts := strings.Split(key, "|")
			if len(parts) >= 2 {
				trustDomain := parts[1]
				metrics.UpdateProviderPoolSize(trustDomain, len(p.clients))
			}
		}
	}
}

func (p *ClientPool) Shutdown() error {
	p.logger.Info("shutting down client pool")

	if p.cleanupCancel != nil {
		p.cleanupCancel()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for key, entry := range p.clients {
		p.logger.Debug("stopping client", "key", key)
		if err := entry.client.Stop(); err != nil {
			p.logger.Error("failed to stop client during shutdown",
				"key", key,
				"error", err,
			)
		}
		metrics.RecordProviderEviction("shutdown")
	}

	p.clients = make(map[string]*poolEntry)

	return nil
}

func (p *ClientPool) GetPoolStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	activeClients := 0
	totalRefCount := 0

	for _, entry := range p.clients {
		if entry.refCount > 0 {
			activeClients++
		}
		totalRefCount += entry.refCount
	}

	return map[string]interface{}{
		"total_clients":  len(p.clients),
		"active_clients": activeClients,
		"total_refs":     totalRefCount,
	}
}

func extractNamespace(selectors []*typesapi.Selector) string {
	for _, selector := range selectors {
		if selector.Type == "k8s" && strings.HasPrefix(selector.Value, "ns:") {
			return strings.TrimPrefix(selector.Value, "ns:")
		}
	}
	return ""
}

func extractServiceAccount(selectors []*typesapi.Selector) string {
	for _, selector := range selectors {
		if selector.Type == "k8s" && strings.HasPrefix(selector.Value, "sa:") {
			return strings.TrimPrefix(selector.Value, "sa:")
		}
	}
	return ""
}
