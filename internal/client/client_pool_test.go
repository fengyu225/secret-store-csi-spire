package client

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/go-hclog"
	typesapi "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

func TestNewClientPool(t *testing.T) {
	tests := []struct {
		name   string
		config PoolConfig
	}{
		{
			name: "with custom timeouts",
			config: PoolConfig{
				StaleTimeout:    5 * time.Minute,
				CleanupInterval: 1 * time.Minute,
			},
		},
		{
			name: "with zero timeouts uses defaults",
			config: PoolConfig{
				StaleTimeout:    0,
				CleanupInterval: 0,
			},
		},
		{
			name: "with negative timeouts uses defaults",
			config: PoolConfig{
				StaleTimeout:    -1 * time.Minute,
				CleanupInterval: -1 * time.Minute,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			pool := NewClientPool(logger, tt.config)

			if pool == nil {
				t.Fatal("Expected pool to be created")
			}

			if pool.clients == nil {
				t.Error("Clients map should be initialized")
			}

			if tt.config.StaleTimeout <= 0 && pool.staleTimeout != 10*time.Minute {
				t.Error("Expected default stale timeout")
			}

			if tt.config.CleanupInterval <= 0 && pool.cleanupInterval != 1*time.Minute {
				t.Error("Expected default cleanup interval")
			}

			// Cleanup
			pool.Shutdown()
		})
	}
}

func TestClientPool_AcquireClient(t *testing.T) {
	tests := []struct {
		name            string
		config1         Config
		config2         Config
		expectSameKey   bool
		expectNewClient bool
	}{
		{
			name: "same config returns same client",
			config1: Config{
				SpireSocketPath:   "/socket",
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "ns:default"},
					{Type: "k8s", Value: "sa:test"},
				},
			},
			config2: Config{
				SpireSocketPath:   "/socket",
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "ns:default"},
					{Type: "k8s", Value: "sa:test"},
				},
			},
			expectSameKey:   true,
			expectNewClient: false,
		},
		{
			name: "different socket path creates new client",
			config1: Config{
				SpireSocketPath:   "/socket1",
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "ns:default"},
				},
			},
			config2: Config{
				SpireSocketPath:   "/socket2",
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "ns:default"},
				},
			},
			expectSameKey:   false,
			expectNewClient: true,
		},
		{
			name: "different trust domain creates new client",
			config1: Config{
				SpireSocketPath:   "/socket",
				SpiffeTrustDomain: "example.org",
				Selectors:         []*typesapi.Selector{},
			},
			config2: Config{
				SpireSocketPath:   "/socket",
				SpiffeTrustDomain: "test.org",
				Selectors:         []*typesapi.Selector{},
			},
			expectSameKey:   false,
			expectNewClient: true,
		},
		{
			name: "different selectors creates new client",
			config1: Config{
				SpireSocketPath:   "/socket",
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "ns:default"},
				},
			},
			config2: Config{
				SpireSocketPath:   "/socket",
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "ns:production"},
				},
			},
			expectSameKey:   false,
			expectNewClient: true,
		},
		{
			name: "selectors in different order but same content",
			config1: Config{
				SpireSocketPath:   "/socket",
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "sa:test"},
					{Type: "k8s", Value: "ns:default"},
				},
			},
			config2: Config{
				SpireSocketPath:   "/socket",
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "ns:default"},
					{Type: "k8s", Value: "sa:test"},
				},
			},
			expectSameKey:   true,
			expectNewClient: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			pool := NewClientPool(logger, PoolConfig{})

			// Mock factory for creating clients
			mockClient1 := NewMockSpireClient(ctrl)
			mockClient1.EXPECT().Start(gomock.Any()).Return(nil).AnyTimes()
			mockClient1.EXPECT().Stop().Return(nil).AnyTimes()

			mockClient2 := NewMockSpireClient(ctrl)
			mockClient2.EXPECT().Start(gomock.Any()).Return(nil).AnyTimes()
			mockClient2.EXPECT().Stop().Return(nil).AnyTimes()

			// Inject test factory
			clientCount := 0
			pool.clientFactory = func(logger hclog.Logger, config Config) (SpireClient, error) {
				clientCount++
				if clientCount == 1 {
					return mockClient1, nil
				}
				return mockClient2, nil
			}

			ctx := context.Background()

			// Acquire first client
			client1, err1 := pool.AcquireClient(ctx, tt.config1)
			if err1 != nil {
				t.Fatalf("Failed to acquire first client: %v", err1)
			}

			// Acquire second client
			client2, err2 := pool.AcquireClient(ctx, tt.config2)
			if err2 != nil {
				t.Fatalf("Failed to acquire second client: %v", err2)
			}

			if tt.expectSameKey {
				if client1 != client2 {
					t.Error("Expected same client instance for same config")
				}
				if len(pool.clients) != 1 {
					t.Errorf("Expected 1 client in pool, got %d", len(pool.clients))
				}
			} else {
				if client1 == client2 {
					t.Error("Expected different client instances for different configs")
				}
				if len(pool.clients) != 2 {
					t.Errorf("Expected 2 clients in pool, got %d", len(pool.clients))
				}
			}

			// Cleanup
			pool.Shutdown()
		})
	}
}

func TestClientPool_ReleaseClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := hclog.NewNullLogger()
	pool := NewClientPool(logger, PoolConfig{})

	config := Config{
		SpireSocketPath:   "/socket",
		SpiffeTrustDomain: "example.org",
		Selectors: []*typesapi.Selector{
			{Type: "k8s", Value: "ns:default"},
		},
	}

	// Mock client
	mockClient := NewMockSpireClient(ctrl)
	mockClient.EXPECT().Start(gomock.Any()).Return(nil)
	mockClient.EXPECT().Stop().Return(nil).AnyTimes()

	// Inject test factory
	pool.clientFactory = func(logger hclog.Logger, cfg Config) (SpireClient, error) {
		return mockClient, nil
	}

	ctx := context.Background()

	// Acquire client multiple times
	pool.AcquireClient(ctx, config)
	pool.AcquireClient(ctx, config)
	pool.AcquireClient(ctx, config)

	key := pool.buildClientKey(config)
	entry := pool.clients[key]
	if entry.refCount != 3 {
		t.Errorf("Expected refCount 3, got %d", entry.refCount)
	}

	// Release client
	pool.ReleaseClient(config)
	if entry.refCount != 2 {
		t.Errorf("Expected refCount 2 after release, got %d", entry.refCount)
	}

	// Release multiple times
	pool.ReleaseClient(config)
	pool.ReleaseClient(config)
	if entry.refCount != 0 {
		t.Errorf("Expected refCount 0, got %d", entry.refCount)
	}

	// Release when already 0 should not go negative
	pool.ReleaseClient(config)
	if entry.refCount != 0 {
		t.Errorf("Expected refCount to remain 0, got %d", entry.refCount)
	}

	// Cleanup
	pool.Shutdown()
}

func TestClientPool_Cleanup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := hclog.NewNullLogger()
	pool := NewClientPool(logger, PoolConfig{
		StaleTimeout:    100 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
	})

	config := Config{
		SpireSocketPath:   "/socket",
		SpiffeTrustDomain: "example.org",
		Selectors:         []*typesapi.Selector{},
	}

	// Mock client
	mockClient := NewMockSpireClient(ctrl)
	mockClient.EXPECT().Start(gomock.Any()).Return(nil)
	mockClient.EXPECT().Stop().Return(nil) // Expect Stop to be called during cleanup

	// Inject test factory
	pool.clientFactory = func(logger hclog.Logger, cfg Config) (SpireClient, error) {
		return mockClient, nil
	}

	ctx := context.Background()

	// Acquire and immediately release client
	pool.AcquireClient(ctx, config)
	pool.ReleaseClient(config)

	// Verify client is in pool with refCount 0
	key := pool.buildClientKey(config)
	if pool.clients[key].refCount != 0 {
		t.Error("Expected refCount 0 after release")
	}

	// Wait for cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Check that stale client was removed
	pool.mu.RLock()
	_, exists := pool.clients[key]
	pool.mu.RUnlock()

	if exists {
		t.Error("Expected stale client to be removed")
	}

	// Cleanup
	pool.Shutdown()
}

func TestClientPool_ConcurrentAccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := hclog.NewNullLogger()
	pool := NewClientPool(logger, PoolConfig{})

	// Create multiple mock clients
	mockClients := make([]SpireClient, 10)
	for i := 0; i < 10; i++ {
		mock := NewMockSpireClient(ctrl)
		mock.EXPECT().Start(gomock.Any()).Return(nil).AnyTimes()
		mock.EXPECT().Stop().Return(nil).AnyTimes()
		mockClients[i] = mock
	}

	clientIndex := 0
	clientMutex := sync.Mutex{}

	// Inject test factory
	pool.clientFactory = func(logger hclog.Logger, config Config) (SpireClient, error) {
		clientMutex.Lock()
		defer clientMutex.Unlock()
		if clientIndex >= len(mockClients) {
			clientIndex = 0
		}
		client := mockClients[clientIndex]
		clientIndex++
		return client, nil
	}

	ctx := context.Background()
	var wg sync.WaitGroup

	// Concurrent acquire and release
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			config := Config{
				SpireSocketPath:   "/socket",
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: fmt.Sprintf("ns:ns%d", id%5)},
				},
			}

			_, err := pool.AcquireClient(ctx, config)
			if err != nil {
				t.Errorf("Failed to acquire client: %v", err)
				return
			}

			// Simulate some work
			time.Sleep(10 * time.Millisecond)

			pool.ReleaseClient(config)
		}(i)
	}

	wg.Wait()

	// Verify pool state
	stats := pool.GetPoolStats()
	t.Logf("Pool stats after concurrent access: %+v", stats)

	// Cleanup
	pool.Shutdown()
}

func TestClientPool_GetPoolStats(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := hclog.NewNullLogger()
	pool := NewClientPool(logger, PoolConfig{})

	// Create mock clients
	mockClient1 := NewMockSpireClient(ctrl)
	mockClient1.EXPECT().Start(gomock.Any()).Return(nil)
	mockClient1.EXPECT().Stop().Return(nil).AnyTimes() // Add Stop expectation

	mockClient2 := NewMockSpireClient(ctrl)
	mockClient2.EXPECT().Start(gomock.Any()).Return(nil)
	mockClient2.EXPECT().Stop().Return(nil).AnyTimes() // Add Stop expectation

	// Inject test factory
	clientCount := 0
	pool.clientFactory = func(logger hclog.Logger, config Config) (SpireClient, error) {
		clientCount++
		if clientCount == 1 {
			return mockClient1, nil
		}
		return mockClient2, nil
	}

	ctx := context.Background()

	// Acquire clients
	config1 := Config{
		SpireSocketPath:   "/socket",
		SpiffeTrustDomain: "example.org",
		Selectors: []*typesapi.Selector{
			{Type: "k8s", Value: "ns:ns1"},
		},
	}

	config2 := Config{
		SpireSocketPath:   "/socket",
		SpiffeTrustDomain: "example.org",
		Selectors: []*typesapi.Selector{
			{Type: "k8s", Value: "ns:ns2"},
		},
	}

	pool.AcquireClient(ctx, config1)
	pool.AcquireClient(ctx, config1) // Same config, increases ref count
	pool.AcquireClient(ctx, config2)

	stats := pool.GetPoolStats()

	if stats["total_clients"].(int) != 2 {
		t.Errorf("Expected 2 total clients, got %d", stats["total_clients"])
	}

	if stats["active_clients"].(int) != 2 {
		t.Errorf("Expected 2 active clients, got %d", stats["active_clients"])
	}

	if stats["total_refs"].(int) != 3 {
		t.Errorf("Expected 3 total refs, got %d", stats["total_refs"])
	}

	// Release one reference
	pool.ReleaseClient(config1)

	stats = pool.GetPoolStats()
	if stats["total_refs"].(int) != 2 {
		t.Errorf("Expected 2 total refs after release, got %d", stats["total_refs"])
	}

	// Cleanup
	pool.Shutdown()
}

func TestClientPool_BuildClientKey(t *testing.T) {
	logger := hclog.NewNullLogger()
	pool := NewClientPool(logger, PoolConfig{})

	tests := []struct {
		name     string
		config   Config
		expected string
	}{
		{
			name: "basic config",
			config: Config{
				SpireSocketPath:   "/socket",
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "ns:default"},
					{Type: "k8s", Value: "sa:test"},
				},
			},
			expected: "/socket||example.org|k8s:ns:default|k8s:sa:test",
		},
		{
			name: "with secondary socket",
			config: Config{
				SpireSocketPath:   "/socket1",
				SpireSocketPath2:  "/socket2",
				SpiffeTrustDomain: "example.org",
				Selectors:         []*typesapi.Selector{},
			},
			expected: "/socket1|/socket2|example.org",
		},
		{
			name: "selectors sorted",
			config: Config{
				SpireSocketPath:   "/socket",
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "sa:test"},
					{Type: "k8s", Value: "ns:default"},
					{Type: "k8s", Value: "pod-uid:123"},
				},
			},
			expected: "/socket||example.org|k8s:ns:default|k8s:pod-uid:123|k8s:sa:test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := pool.buildClientKey(tt.config)
			if key != tt.expected {
				t.Errorf("Expected key %q, got %q", tt.expected, key)
			}
		})
	}

	// Cleanup
	pool.Shutdown()
}

func TestClientPool_AcquireClient_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := hclog.NewNullLogger()
	pool := NewClientPool(logger, PoolConfig{})

	config := Config{
		SpireSocketPath:   "/socket",
		SpiffeTrustDomain: "example.org",
	}

	t.Run("factory returns error", func(t *testing.T) {
		// Inject factory that returns error
		pool.clientFactory = func(logger hclog.Logger, cfg Config) (SpireClient, error) {
			return nil, fmt.Errorf("failed to create client")
		}

		ctx := context.Background()
		client, err := pool.AcquireClient(ctx, config)

		if err == nil {
			t.Fatal("Expected error but got none")
		}
		if client != nil {
			t.Error("Expected nil client on error")
		}
		if !strings.Contains(err.Error(), "failed to create client") {
			t.Errorf("Expected error message about client creation, got: %v", err)
		}
	})

	t.Run("start returns error", func(t *testing.T) {
		mockClient := NewMockSpireClient(ctrl)
		mockClient.EXPECT().Start(gomock.Any()).Return(fmt.Errorf("failed to start"))

		// Inject factory that returns mock client
		pool.clientFactory = func(logger hclog.Logger, cfg Config) (SpireClient, error) {
			return mockClient, nil
		}

		ctx := context.Background()
		client, err := pool.AcquireClient(ctx, config)

		if err == nil {
			t.Fatal("Expected error but got none")
		}
		if client != nil {
			t.Error("Expected nil client on error")
		}
		if !strings.Contains(err.Error(), "failed to start") {
			t.Errorf("Expected error message about start failure, got: %v", err)
		}
	})

	// Cleanup
	pool.Shutdown()
}

func TestClientPool_Shutdown(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := hclog.NewNullLogger()
	pool := NewClientPool(logger, PoolConfig{
		CleanupInterval: 50 * time.Millisecond,
	})

	// Create mock clients
	mockClient1 := NewMockSpireClient(ctrl)
	mockClient1.EXPECT().Start(gomock.Any()).Return(nil).Times(1)
	mockClient1.EXPECT().Stop().Return(nil).Times(1) // Called exactly once during shutdown

	mockClient2 := NewMockSpireClient(ctrl)
	mockClient2.EXPECT().Start(gomock.Any()).Return(nil).Times(1)
	mockClient2.EXPECT().Stop().Return(nil).Times(1) // Called exactly once during shutdown

	callCount := 0
	pool.clientFactory = func(logger hclog.Logger, config Config) (SpireClient, error) {
		callCount++
		switch callCount {
		case 1:
			return mockClient1, nil
		case 2:
			return mockClient2, nil
		default:
			t.Fatalf("Unexpected call to clientFactory: call %d", callCount)
			return nil, fmt.Errorf("unexpected call")
		}
	}

	ctx := context.Background()

	// Acquire clients
	config1 := Config{
		SpireSocketPath:   "/socket",
		SpiffeTrustDomain: "example.org",
		Selectors: []*typesapi.Selector{
			{Type: "k8s", Value: "ns:ns1"},
		},
	}

	config2 := Config{
		SpireSocketPath:   "/socket",
		SpiffeTrustDomain: "example.org",
		Selectors: []*typesapi.Selector{
			{Type: "k8s", Value: "ns:ns2"},
		},
	}

	pool.AcquireClient(ctx, config1)
	pool.AcquireClient(ctx, config2)

	// Verify clients are in pool
	if len(pool.clients) != 2 {
		t.Errorf("Expected 2 clients in pool before shutdown, got %d", len(pool.clients))
	}

	// Shutdown pool
	err := pool.Shutdown()
	if err != nil {
		t.Errorf("Unexpected error during shutdown: %v", err)
	}

	// Verify all clients were stopped and removed
	if len(pool.clients) != 0 {
		t.Errorf("Expected 0 clients after shutdown, got %d", len(pool.clients))
	}

	// Note: ClientPool doesn't track shutdown state, so acquiring after shutdown
	// will create a new client. This is by design - the pool can be reused after shutdown.
}

func TestClientPool_MultipleReleasesAndCleanup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := hclog.NewNullLogger()
	pool := NewClientPool(logger, PoolConfig{
		StaleTimeout:    100 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
	})

	config := Config{
		SpireSocketPath:   "/socket",
		SpiffeTrustDomain: "example.org",
	}

	mockClient := NewMockSpireClient(ctrl)
	mockClient.EXPECT().Start(gomock.Any()).Return(nil)
	mockClient.EXPECT().Stop().Return(nil).MaxTimes(1) // Should only be called once

	pool.clientFactory = func(logger hclog.Logger, cfg Config) (SpireClient, error) {
		return mockClient, nil
	}

	ctx := context.Background()

	// Acquire and release multiple times
	for i := 0; i < 5; i++ {
		client, err := pool.AcquireClient(ctx, config)
		if err != nil {
			t.Fatalf("Failed to acquire client on iteration %d: %v", i, err)
		}
		if client == nil {
			t.Fatalf("Got nil client on iteration %d", i)
		}
		pool.ReleaseClient(config)
	}

	// Verify client is still in pool with refCount 0
	key := pool.buildClientKey(config)
	pool.mu.RLock()
	entry, exists := pool.clients[key]
	pool.mu.RUnlock()

	if !exists {
		t.Error("Client should still be in pool")
	}
	if entry.refCount != 0 {
		t.Errorf("Expected refCount 0, got %d", entry.refCount)
	}

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)

	// Verify client was removed
	pool.mu.RLock()
	_, exists = pool.clients[key]
	pool.mu.RUnlock()

	if exists {
		t.Error("Expected client to be removed after cleanup")
	}

	// Cleanup
	pool.Shutdown()
}
