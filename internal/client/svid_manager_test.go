package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	delegatedapi "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	typesapi "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

func TestNewSVIDManager(t *testing.T) {
	logger := hclog.NewNullLogger()
	sm := newSVIDManager(logger)

	if sm == nil {
		t.Fatal("Expected non-nil SVID manager")
	}
	if sm.logger == nil {
		t.Error("Logger should be set")
	}
	if sm.store == nil {
		t.Error("Store should be initialized")
	}
	if sm.parsedCerts == nil {
		t.Error("ParsedCerts should be initialized")
	}
	if sm.waiters == nil {
		t.Error("Waiters should be initialized")
	}
}

func TestSVIDManager_WaitForSVID(t *testing.T) {
	tests := []struct {
		name          string
		spiffeID      string
		timeout       time.Duration
		preloadSVID   bool
		triggerNotify bool
		expectError   bool
	}{
		{
			name:        "SVID already available",
			spiffeID:    "spiffe://example.org/test",
			timeout:     1 * time.Second,
			preloadSVID: true,
			expectError: false,
		},
		{
			name:          "SVID becomes available",
			spiffeID:      "spiffe://example.org/test",
			timeout:       1 * time.Second,
			triggerNotify: true,
			expectError:   false,
		},
		{
			name:        "timeout waiting for SVID",
			spiffeID:    "spiffe://example.org/test",
			timeout:     100 * time.Millisecond,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			sm := newSVIDManager(logger)
			ctx := context.Background()

			if tt.preloadSVID {
				sm.store[tt.spiffeID] = createMockSVID()
			}

			if tt.triggerNotify {
				go func() {
					time.Sleep(50 * time.Millisecond)
					sm.store[tt.spiffeID] = createMockSVID()
					sm.notifyWaiters(tt.spiffeID)
				}()
			}

			err := sm.waitForSVID(ctx, tt.spiffeID, tt.timeout)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSVIDManager_HandleUpdate(t *testing.T) {
	tests := []struct {
		name        string
		trustDomain string
		svids       []*delegatedapi.X509SVIDWithKey
		expectCount int
	}{
		{
			name:        "single SVID update",
			trustDomain: "example.org",
			svids: []*delegatedapi.X509SVIDWithKey{
				createMockSVIDWithPath("example.org", "/test1"),
			},
			expectCount: 1,
		},
		{
			name:        "multiple SVID update",
			trustDomain: "example.org",
			svids: []*delegatedapi.X509SVIDWithKey{
				createMockSVIDWithPath("example.org", "/test1"),
				createMockSVIDWithPath("example.org", "/test2"),
				createMockSVIDWithPath("example.org", "/test3"),
			},
			expectCount: 3,
		},
		{
			name:        "trust domain mismatch",
			trustDomain: "example.org",
			svids: []*delegatedapi.X509SVIDWithKey{
				createMockSVIDWithPath("other.org", "/test1"),
			},
			expectCount: 0,
		},
		{
			name:        "mixed trust domains",
			trustDomain: "example.org",
			svids: []*delegatedapi.X509SVIDWithKey{
				createMockSVIDWithPath("example.org", "/test1"),
				createMockSVIDWithPath("other.org", "/test2"),
				createMockSVIDWithPath("example.org", "/test3"),
			},
			expectCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			sm := newSVIDManager(logger)

			sm.handleUpdate(tt.svids, tt.trustDomain)

			if len(sm.store) != tt.expectCount {
				t.Errorf("Expected %d SVIDs in store, got %d", tt.expectCount, len(sm.store))
			}
		})
	}
}

func TestSVIDManager_GetCertificate(t *testing.T) {
	tests := []struct {
		name        string
		spiffeID    string
		setupStore  func(*svidManager)
		expectError bool
		errorMsg    string
	}{
		{
			name:     "valid certificate",
			spiffeID: "spiffe://example.org/test",
			setupStore: func(sm *svidManager) {
				cert, key := generateTestCertAndKey()
				keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
				sm.store["spiffe://example.org/test"] = &delegatedapi.X509SVIDWithKey{
					X509Svid: &typesapi.X509SVID{
						Id: &typesapi.SPIFFEID{
							TrustDomain: "example.org",
							Path:        "/test",
						},
						CertChain: [][]byte{cert.Raw},
						ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
					},
					X509SvidKey: keyBytes,
				}
			},
			expectError: false,
		},
		{
			name:        "SVID not found",
			spiffeID:    "spiffe://example.org/missing",
			setupStore:  func(sm *svidManager) {},
			expectError: true,
			errorMsg:    "no SPIFFE ID",
		},
		{
			name:     "empty certificate chain",
			spiffeID: "spiffe://example.org/test",
			setupStore: func(sm *svidManager) {
				sm.store["spiffe://example.org/test"] = &delegatedapi.X509SVIDWithKey{
					X509Svid: &typesapi.X509SVID{
						Id: &typesapi.SPIFFEID{
							TrustDomain: "example.org",
							Path:        "/test",
						},
						CertChain: [][]byte{},
						ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
					},
				}
			},
			expectError: true,
			errorMsg:    "no certificate chain",
		},
		{
			name:     "expired SVID",
			spiffeID: "spiffe://example.org/test",
			setupStore: func(sm *svidManager) {
				cert, key := generateTestCertAndKey()
				keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
				sm.store["spiffe://example.org/test"] = &delegatedapi.X509SVIDWithKey{
					X509Svid: &typesapi.X509SVID{
						Id: &typesapi.SPIFFEID{
							TrustDomain: "example.org",
							Path:        "/test",
						},
						CertChain: [][]byte{cert.Raw},
						ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
					},
					X509SvidKey: keyBytes,
				}
			},
			expectError: true,
			errorMsg:    "has expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			sm := newSVIDManager(logger)

			tt.setupStore(sm)

			cert, err := sm.getCertificate(tt.spiffeID)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if cert == nil {
					t.Error("Expected certificate but got nil")
				}
			}
		})
	}
}

func TestSVIDManager_ValidateExpiration(t *testing.T) {
	logger := hclog.NewNullLogger()
	sm := newSVIDManager(logger)

	tests := []struct {
		name        string
		svid        *delegatedapi.X509SVIDWithKey
		expectError bool
		expectWarn  bool
	}{
		{
			name: "valid SVID",
			svid: &delegatedapi.X509SVIDWithKey{
				X509Svid: &typesapi.X509SVID{
					ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
				},
			},
			expectError: false,
			expectWarn:  false,
		},
		{
			name: "expired SVID",
			svid: &delegatedapi.X509SVIDWithKey{
				X509Svid: &typesapi.X509SVID{
					ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
				},
			},
			expectError: true,
			expectWarn:  false,
		},
		{
			name: "SVID close to expiry",
			svid: &delegatedapi.X509SVIDWithKey{
				X509Svid: &typesapi.X509SVID{
					ExpiresAt: time.Now().Add(3 * time.Minute).Unix(),
				},
			},
			expectError: false,
			expectWarn:  true,
		},
		{
			name: "SVID with zero expiry",
			svid: &delegatedapi.X509SVIDWithKey{
				X509Svid: &typesapi.X509SVID{
					ExpiresAt: 0,
				},
			},
			expectError: false,
			expectWarn:  false,
		},
		{
			name: "SVID with nil X509Svid",
			svid: &delegatedapi.X509SVIDWithKey{
				X509Svid: nil,
			},
			expectError: false,
			expectWarn:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sm.validateExpiration(tt.svid, "test-spiffe-id")

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSVIDManager_ParseCertificate(t *testing.T) {
	logger := hclog.NewNullLogger()
	sm := newSVIDManager(logger)

	cert, key := generateTestCertAndKey()
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)

	tests := []struct {
		name        string
		svid        *delegatedapi.X509SVIDWithKey
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid certificate",
			svid: &delegatedapi.X509SVIDWithKey{
				X509Svid: &typesapi.X509SVID{
					CertChain: [][]byte{cert.Raw},
				},
				X509SvidKey: keyBytes,
			},
			expectError: false,
		},
		{
			name: "empty certificate chain",
			svid: &delegatedapi.X509SVIDWithKey{
				X509Svid: &typesapi.X509SVID{
					CertChain: [][]byte{},
				},
				X509SvidKey: keyBytes,
			},
			expectError: true,
			errorMsg:    "no certificate chain",
		},
		{
			name: "invalid certificate",
			svid: &delegatedapi.X509SVIDWithKey{
				X509Svid: &typesapi.X509SVID{
					CertChain: [][]byte{[]byte("invalid")},
				},
				X509SvidKey: keyBytes,
			},
			expectError: true,
			errorMsg:    "failed to parse certificate",
		},
		{
			name: "invalid private key",
			svid: &delegatedapi.X509SVIDWithKey{
				X509Svid: &typesapi.X509SVID{
					CertChain: [][]byte{cert.Raw},
				},
				X509SvidKey: []byte("invalid-key"),
			},
			expectError: true,
			errorMsg:    "failed to parse private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsCert, err := sm.parseCertificate(tt.svid, "test-spiffe-id")

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tlsCert == nil {
					t.Error("Expected TLS certificate but got nil")
				} else {
					if len(tlsCert.Certificate) == 0 {
						t.Error("TLS certificate should have certificate chain")
					}
					if tlsCert.PrivateKey == nil {
						t.Error("TLS certificate should have private key")
					}
				}
			}
		})
	}
}

func TestSVIDManager_Size(t *testing.T) {
	logger := hclog.NewNullLogger()
	sm := newSVIDManager(logger)

	// Initially empty
	if sm.size() != 0 {
		t.Errorf("Expected size 0, got %d", sm.size())
	}

	// Add some SVIDs
	sm.store["spiffe://example.org/test1"] = createMockSVID()
	if sm.size() != 1 {
		t.Errorf("Expected size 1, got %d", sm.size())
	}

	sm.store["spiffe://example.org/test2"] = createMockSVID()
	if sm.size() != 2 {
		t.Errorf("Expected size 2, got %d", sm.size())
	}
}

func TestSVIDManager_NotifyWaiters(t *testing.T) {
	logger := hclog.NewNullLogger()
	sm := newSVIDManager(logger)

	spiffeID := "spiffe://example.org/test"

	// Register a waiter
	waitChan := sm.registerWaiter(spiffeID)

	// Verify waiter is registered
	if _, exists := sm.waiters[spiffeID]; !exists {
		t.Error("Waiter should be registered")
	}

	// Notify in goroutine
	go func() {
		time.Sleep(50 * time.Millisecond)
		sm.notifyWaiters(spiffeID)
	}()

	// Wait for notification
	select {
	case <-waitChan:
	case <-time.After(500 * time.Millisecond):
		t.Error("Timeout waiting for notification")
	}

	// Verify waiter was removed
	if _, exists := sm.waiters[spiffeID]; exists {
		t.Error("Waiter should be removed after notification")
	}
}

func createMockSVID() *delegatedapi.X509SVIDWithKey {
	cert, key := generateTestCertAndKey()
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)

	return &delegatedapi.X509SVIDWithKey{
		X509Svid: &typesapi.X509SVID{
			Id: &typesapi.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/test",
			},
			CertChain: [][]byte{cert.Raw},
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		},
		X509SvidKey: keyBytes,
	}
}

func createMockSVIDWithPath(trustDomain, path string) *delegatedapi.X509SVIDWithKey {
	cert, key := generateTestCertAndKey()
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)

	return &delegatedapi.X509SVIDWithKey{
		X509Svid: &typesapi.X509SVID{
			Id: &typesapi.SPIFFEID{
				TrustDomain: trustDomain,
				Path:        path,
			},
			CertChain: [][]byte{cert.Raw},
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		},
		X509SvidKey: keyBytes,
	}
}

func generateTestCertAndKey() (*x509.Certificate, *rsa.PrivateKey) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	return cert, key
}

func TestSVIDManager_CleanupRoutine(t *testing.T) {
	tests := []struct {
		name              string
		setupSVIDs        func(*svidManager)
		waitDuration      time.Duration
		expectedRemaining int
	}{
		{
			name: "cleanup removes expired SVIDs",
			setupSVIDs: func(sm *svidManager) {
				expiredSVID := createMockSVID()
				expiredSVID.X509Svid.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()
				sm.store["spiffe://example.org/expired"] = expiredSVID

				validSVID := createMockSVID()
				validSVID.X509Svid.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
				sm.store["spiffe://example.org/valid"] = validSVID

				zeroExpirySVID := createMockSVID()
				zeroExpirySVID.X509Svid.ExpiresAt = 0
				sm.store["spiffe://example.org/zero"] = zeroExpirySVID
			},
			waitDuration:      100 * time.Millisecond,
			expectedRemaining: 2,
		},
		{
			name:              "cleanup handles empty store",
			setupSVIDs:        func(sm *svidManager) {},
			waitDuration:      100 * time.Millisecond,
			expectedRemaining: 0,
		},
		{
			name: "cleanup removes multiple expired SVIDs",
			setupSVIDs: func(sm *svidManager) {
				for i := 0; i < 5; i++ {
					expiredSVID := createMockSVID()
					expiredSVID.X509Svid.ExpiresAt = time.Now().Add(-time.Duration(i+1) * time.Hour).Unix()
					sm.store[fmt.Sprintf("spiffe://example.org/expired%d", i)] = expiredSVID
				}

				validSVID := createMockSVID()
				validSVID.X509Svid.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
				sm.store["spiffe://example.org/valid"] = validSVID
			},
			waitDuration:      100 * time.Millisecond,
			expectedRemaining: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			sm := newSVIDManager(logger)

			sm.stopCleanup()

			tt.setupSVIDs(sm)

			sm.performCleanup()

			if len(sm.store) != tt.expectedRemaining {
				t.Errorf("Expected %d SVIDs remaining, got %d", tt.expectedRemaining, len(sm.store))
			}

			for spiffeID, svid := range sm.store {
				if svid.X509Svid != nil && svid.X509Svid.ExpiresAt > 0 {
					expiresAt := time.Unix(svid.X509Svid.ExpiresAt, 0)
					if time.Now().After(expiresAt) {
						t.Errorf("Expired SVID %s should have been removed", spiffeID)
					}
				}
			}
		})
	}
}

func TestSVIDManager_StopCleanup(t *testing.T) {
	logger := hclog.NewNullLogger()
	sm := newSVIDManager(logger)

	if sm.cleanupCtx == nil {
		t.Error("Cleanup context should be initialized")
	}

	sm.stopCleanup()

	select {
	case <-sm.cleanupCtx.Done():
	default:
		t.Error("Cleanup context should be cancelled after stopCleanup")
	}

	// Calling stopCleanup again should not panic
	sm.stopCleanup()
}

func TestSVIDManager_WaitForSVIDWithExpiredSVID(t *testing.T) {
	tests := []struct {
		name          string
		setupSVID     func(*svidManager, string)
		expectWait    bool
		triggerUpdate bool
	}{
		{
			name: "expired SVID triggers wait",
			setupSVID: func(sm *svidManager, spiffeID string) {
				expiredSVID := createMockSVID()
				expiredSVID.X509Svid.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()
				sm.store[spiffeID] = expiredSVID
			},
			expectWait:    true,
			triggerUpdate: true,
		},
		{
			name: "valid SVID returns immediately",
			setupSVID: func(sm *svidManager, spiffeID string) {
				validSVID := createMockSVID()
				validSVID.X509Svid.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
				sm.store[spiffeID] = validSVID
			},
			expectWait: false,
		},
		{
			name: "SVID with zero expiry returns immediately",
			setupSVID: func(sm *svidManager, spiffeID string) {
				zeroExpirySVID := createMockSVID()
				zeroExpirySVID.X509Svid.ExpiresAt = 0
				sm.store[spiffeID] = zeroExpirySVID
			},
			expectWait: false,
		},
		{
			name: "SVID with nil X509Svid returns immediately",
			setupSVID: func(sm *svidManager, spiffeID string) {
				nilSVID := &delegatedapi.X509SVIDWithKey{
					X509Svid: nil,
				}
				sm.store[spiffeID] = nilSVID
			},
			expectWait: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			sm := newSVIDManager(logger)
			ctx := context.Background()
			spiffeID := "spiffe://example.org/test"

			tt.setupSVID(sm, spiffeID)

			if tt.expectWait {
				done := make(chan error, 1)
				go func() {
					err := sm.waitForSVID(ctx, spiffeID, 500*time.Millisecond)
					done <- err
				}()

				time.Sleep(50 * time.Millisecond)

				sm.waitersMutex.Lock()
				_, hasWaiter := sm.waiters[spiffeID]
				sm.waitersMutex.Unlock()

				if !hasWaiter {
					t.Error("Expected waiter to be registered for expired SVID")
				}

				if tt.triggerUpdate {
					validSVID := createMockSVID()
					validSVID.X509Svid.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
					sm.mu.Lock()
					sm.store[spiffeID] = validSVID
					sm.mu.Unlock()
					sm.notifyWaiters(spiffeID)

					select {
					case err := <-done:
						if err != nil {
							t.Errorf("Unexpected error: %v", err)
						}
					case <-time.After(1 * time.Second):
						t.Error("waitForSVID should have completed after update")
					}
				}
			} else {
				// Should return immediately
				err := sm.waitForSVID(ctx, spiffeID, 100*time.Millisecond)
				if err != nil {
					t.Errorf("Expected immediate return but got error: %v", err)
				}
			}
		})
	}
}

func TestSVIDManager_HandleUpdateAlwaysNotifies(t *testing.T) {
	logger := hclog.NewNullLogger()
	sm := newSVIDManager(logger)

	spiffeID := "spiffe://example.org/test"

	existingSVID := createMockSVIDWithPath("example.org", "/test")
	sm.store[spiffeID] = existingSVID

	waitChan := sm.registerWaiter(spiffeID)

	newSVID := createMockSVIDWithPath("example.org", "/test")
	newSVID.X509Svid.ExpiresAt = time.Now().Add(2 * time.Hour).Unix()

	go func() {
		sm.handleUpdate([]*delegatedapi.X509SVIDWithKey{newSVID}, "example.org")
	}()

	select {
	case <-waitChan:
	case <-time.After(500 * time.Millisecond):
		t.Error("Expected notification for existing SVID update")
	}

	sm.mu.RLock()
	updatedSVID := sm.store[spiffeID]
	sm.mu.RUnlock()

	if updatedSVID.X509Svid.ExpiresAt != newSVID.X509Svid.ExpiresAt {
		t.Error("SVID should have been updated with new expiry")
	}
}

func TestSVIDManager_PerformCleanupRemovesParsedCerts(t *testing.T) {
	logger := hclog.NewNullLogger()
	sm := newSVIDManager(logger)

	// Add expired SVID with parsed cert
	expiredSVID := createMockSVID()
	expiredSVID.X509Svid.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()
	spiffeID := "spiffe://example.org/expired"
	sm.store[spiffeID] = expiredSVID
	sm.parsedCerts[spiffeID] = []*x509.Certificate{{}}

	validSVID := createMockSVID()
	validSVID.X509Svid.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
	validSpiffeID := "spiffe://example.org/valid"
	sm.store[validSpiffeID] = validSVID
	sm.parsedCerts[validSpiffeID] = []*x509.Certificate{{}}

	sm.performCleanup()

	// Verify expired SVID and its parsed cert are removed
	if _, exists := sm.store[spiffeID]; exists {
		t.Error("Expired SVID should have been removed from store")
	}
	if _, exists := sm.parsedCerts[spiffeID]; exists {
		t.Error("Expired SVID's parsed cert should have been removed")
	}

	// Verify valid SVID and its parsed cert remain
	if _, exists := sm.store[validSpiffeID]; !exists {
		t.Error("Valid SVID should remain in store")
	}
	if _, exists := sm.parsedCerts[validSpiffeID]; !exists {
		t.Error("Valid SVID's parsed cert should remain")
	}
}
