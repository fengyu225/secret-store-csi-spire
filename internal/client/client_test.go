package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/go-hclog"
	delegatedapi "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	typesapi "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"spire-csi-provider/internal/metrics"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: Config{
				SpireSocketPath:   "/run/spire/socket",
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "ns:default"},
				},
				RotatedQueueSize: 100,
			},
			wantErr: false,
		},
		{
			name: "missing socket path",
			config: Config{
				SpiffeTrustDomain: "example.org",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "ns:default"},
				},
			},
			wantErr: true,
			errMsg:  "SPIRE socket path not specified",
		},
		{
			name: "missing trust domain",
			config: Config{
				SpireSocketPath: "/run/spire/socket",
				Selectors: []*typesapi.Selector{
					{Type: "k8s", Value: "ns:default"},
				},
			},
			wantErr: true,
			errMsg:  "SPIRE trust domain not specified",
		},
		{
			name: "zero rotated queue size uses default",
			config: Config{
				SpireSocketPath:   "/run/spire/socket",
				SpiffeTrustDomain: "example.org",
				RotatedQueueSize:  0,
			},
			wantErr: false,
		},
		{
			name: "negative rotated queue size uses default",
			config: Config{
				SpireSocketPath:   "/run/spire/socket",
				SpiffeTrustDomain: "example.org",
				RotatedQueueSize:  -1,
			},
			wantErr: false,
		},
		{
			name: "with pod context",
			config: Config{
				SpireSocketPath:   "/run/spire/socket",
				SpiffeTrustDomain: "example.org",
				PodContext: metrics.PodContext{
					Namespace:      "kube-system",
					ServiceAccount: "admin",
					PodUID:         "123",
					PodName:        "test-pod",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			client, err := New(logger, tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("Expected error %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if client == nil {
					t.Error("Expected client to be created")
				} else {
					if client.config.SpireSocketPath != tt.config.SpireSocketPath {
						t.Error("Socket path not set correctly")
					}
					if client.config.SpiffeTrustDomain != tt.config.SpiffeTrustDomain {
						t.Error("Trust domain not set correctly")
					}
					if tt.config.RotatedQueueSize <= 0 && client.config.RotatedQueueSize != 1024 {
						t.Error("Default rotated queue size not set")
					}
				}
			}
		})
	}
}

func TestClient_WaitForSVID(t *testing.T) {
	tests := []struct {
		name           string
		spiffeID       string
		timeout        time.Duration
		preloadSVID    bool
		simulateUpdate bool
		expectTimeout  bool
		expectError    bool
	}{
		{
			name:        "SVID already available",
			spiffeID:    "spiffe://example.org/test",
			timeout:     1 * time.Second,
			preloadSVID: true,
			expectError: false,
		},
		{
			name:           "SVID becomes available",
			spiffeID:       "spiffe://example.org/test",
			timeout:        2 * time.Second,
			preloadSVID:    false,
			simulateUpdate: true,
			expectError:    false,
		},
		{
			name:          "timeout waiting for SVID",
			spiffeID:      "spiffe://example.org/test",
			timeout:       100 * time.Millisecond,
			preloadSVID:   false,
			expectTimeout: true,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			config := Config{
				SpireSocketPath:   "/run/spire/socket",
				SpiffeTrustDomain: "example.org",
			}

			client, _ := New(logger, config)
			ctx := context.Background()

			if tt.preloadSVID {
				// Preload SVID in store through the manager
				client.svidManager.store[tt.spiffeID] = &delegatedapi.X509SVIDWithKey{
					X509Svid: &typesapi.X509SVID{
						Id: &typesapi.SPIFFEID{
							TrustDomain: "example.org",
							Path:        "/test",
						},
						ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
					},
				}
			}

			if tt.simulateUpdate {
				// Simulate SVID becoming available after a delay
				go func() {
					time.Sleep(100 * time.Millisecond)
					client.svidManager.mu.Lock()
					client.svidManager.store[tt.spiffeID] = &delegatedapi.X509SVIDWithKey{
						X509Svid: &typesapi.X509SVID{
							Id: &typesapi.SPIFFEID{
								TrustDomain: "example.org",
								Path:        "/test",
							},
							ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
						},
					}
					client.svidManager.mu.Unlock()

					// Notify waiter
					client.svidManager.waitersMutex.Lock()
					if waitChan, exists := client.svidManager.waiters[tt.spiffeID]; exists {
						close(waitChan)
						delete(client.svidManager.waiters, tt.spiffeID)
					}
					client.svidManager.waitersMutex.Unlock()
				}()
			}

			// Mock the stream manager to be healthy
			client.streamManager.initialized.Store(true)
			client.streamManager.streamsHealthy.Store(true)

			err := client.WaitForSVID(ctx, tt.spiffeID, tt.timeout)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if tt.expectTimeout && !errors.Is(err, context.DeadlineExceeded) && !contains(err.Error(), "timeout") {
					t.Errorf("Expected timeout error, got: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestClient_WaitForTrustBundle(t *testing.T) {
	tests := []struct {
		name           string
		timeout        time.Duration
		preloadBundle  bool
		simulateUpdate bool
		expectTimeout  bool
		expectError    bool
	}{
		{
			name:          "bundle already available",
			timeout:       1 * time.Second,
			preloadBundle: true,
			expectError:   false,
		},
		{
			name:           "bundle becomes available",
			timeout:        2 * time.Second,
			preloadBundle:  false,
			simulateUpdate: true,
			expectError:    false,
		},
		{
			name:          "timeout waiting for bundle",
			timeout:       100 * time.Millisecond,
			preloadBundle: false,
			expectTimeout: true,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			config := Config{
				SpireSocketPath:   "/run/spire/socket",
				SpiffeTrustDomain: "example.org",
			}

			client, _ := New(logger, config)
			ctx := context.Background()

			if tt.preloadBundle {
				// Preload trust bundle through the manager
				cert := generateTestCACertificate(t)
				client.bundleManager.parsedCerts["example.org"] = []*x509.Certificate{cert}
			}

			if tt.simulateUpdate {
				// Simulate bundle becoming available after a delay
				go func() {
					time.Sleep(100 * time.Millisecond)
					cert := generateTestCACertificate(t)
					client.bundleManager.mu.Lock()
					client.bundleManager.parsedCerts["example.org"] = []*x509.Certificate{cert}
					client.bundleManager.mu.Unlock()

					// Signal bundle ready
					client.bundleManager.readyOnce.Do(func() {
						client.bundleManager.ready = make(chan struct{})
					})
					select {
					case <-client.bundleManager.ready:
					default:
						close(client.bundleManager.ready)
					}
				}()
			}

			// Mock the stream manager to be healthy
			client.streamManager.initialized.Store(true)
			client.streamManager.streamsHealthy.Store(true)

			err := client.WaitForTrustBundle(ctx, tt.timeout)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if tt.expectTimeout && !contains(err.Error(), "timeout") {
					t.Errorf("Expected timeout error, got: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestClient_GetCACertificates(t *testing.T) {
	tests := []struct {
		name          string
		setupCerts    map[string][]*x509.Certificate
		expectError   bool
		expectedCount int
	}{
		{
			name: "single trust domain",
			setupCerts: map[string][]*x509.Certificate{
				"example.org": {
					generateTestCACertificate(t),
					generateTestCACertificate(t),
				},
			},
			expectError:   false,
			expectedCount: 2,
		},
		{
			name: "multiple trust domains",
			setupCerts: map[string][]*x509.Certificate{
				"example.org": {
					generateTestCACertificate(t),
				},
				"test.org": {
					generateTestCACertificate(t),
					generateTestCACertificate(t),
				},
			},
			expectError:   false,
			expectedCount: 3,
		},
		{
			name:          "no certificates available",
			setupCerts:    map[string][]*x509.Certificate{},
			expectError:   true,
			expectedCount: 0,
		},
		{
			name:          "nil parsed certs",
			setupCerts:    nil,
			expectError:   true,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			config := Config{
				SpireSocketPath:   "/run/spire/socket",
				SpiffeTrustDomain: "example.org",
			}

			client, _ := New(logger, config)
			client.bundleManager.parsedCerts = tt.setupCerts

			// Mock the stream manager to be healthy
			client.streamManager.initialized.Store(true)
			client.streamManager.streamsHealthy.Store(true)

			ctx := context.Background()
			certs, err := client.GetCACertificates(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(certs) != tt.expectedCount {
					t.Errorf("Expected %d certificates, got %d", tt.expectedCount, len(certs))
				}
			}
		})
	}
}

func TestClient_GetCertificateForIdentity(t *testing.T) {
	tests := []struct {
		name        string
		spiffeID    string
		setupSVID   bool
		invalidCert bool
		emptyChain  bool
		badKey      bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid certificate",
			spiffeID:    "spiffe://example.org/test",
			setupSVID:   true,
			expectError: false,
		},
		{
			name:        "SVID not found",
			spiffeID:    "spiffe://example.org/missing",
			setupSVID:   false,
			expectError: true,
			errorMsg:    "no SPIFFE ID for",
		},
		{
			name:        "empty certificate chain",
			spiffeID:    "spiffe://example.org/test",
			setupSVID:   true,
			emptyChain:  true,
			expectError: true,
			errorMsg:    "no certificate chain",
		},
		{
			name:        "invalid certificate in chain",
			spiffeID:    "spiffe://example.org/test",
			setupSVID:   true,
			invalidCert: true,
			expectError: true,
			errorMsg:    "failed to parse certificate",
		},
		{
			name:        "invalid private key",
			spiffeID:    "spiffe://example.org/test",
			setupSVID:   true,
			badKey:      true,
			expectError: true,
			errorMsg:    "failed to parse private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			config := Config{
				SpireSocketPath:   "/run/spire/socket",
				SpiffeTrustDomain: "example.org",
			}

			client, _ := New(logger, config)

			if tt.setupSVID {
				cert, key := generateTestCertificate(t)
				keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)

				svid := &delegatedapi.X509SVIDWithKey{
					X509Svid: &typesapi.X509SVID{
						Id: &typesapi.SPIFFEID{
							TrustDomain: "example.org",
							Path:        "/test",
						},
						ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
					},
					X509SvidKey: keyBytes,
				}

				if tt.emptyChain {
					svid.X509Svid.CertChain = [][]byte{}
				} else if tt.invalidCert {
					svid.X509Svid.CertChain = [][]byte{[]byte("invalid-cert")}
				} else {
					svid.X509Svid.CertChain = [][]byte{cert.Raw}
				}

				if tt.badKey {
					svid.X509SvidKey = []byte("invalid-key")
				}

				client.svidManager.store[tt.spiffeID] = svid
			}

			// Mock the stream manager to be healthy
			client.streamManager.initialized.Store(true)
			client.streamManager.streamsHealthy.Store(true)

			tlsCert, err := client.GetCertificateForIdentity(tt.spiffeID)

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
					t.Error("Expected certificate but got nil")
				}
			}
		})
	}
}

func TestClient_FetchJWTSVID(t *testing.T) {
	tests := []struct {
		name           string
		spiffeID       string
		audiences      []string
		cachedToken    string
		cachedExpiry   time.Time
		fetchResponse  *delegatedapi.FetchJWTSVIDsResponse
		fetchError     error
		expectCacheHit bool
		expectError    bool
		errorMsg       string
	}{
		{
			name:      "successful fetch",
			spiffeID:  "spiffe://example.org/test",
			audiences: []string{"audience1"},
			fetchResponse: &delegatedapi.FetchJWTSVIDsResponse{
				Svids: []*typesapi.JWTSVID{
					{
						Token:     "test-token",
						ExpiresAt: time.Now().Add(2 * time.Hour).Unix(),
					},
				},
			},
			expectError: false,
		},
		{
			name:           "cache hit",
			spiffeID:       "spiffe://example.org/test",
			audiences:      []string{"audience1"},
			cachedToken:    "cached-token",
			cachedExpiry:   time.Now().Add(2 * time.Hour),
			expectCacheHit: true,
			expectError:    false,
		},
		{
			name:           "cache miss - expired",
			spiffeID:       "spiffe://example.org/test",
			audiences:      []string{"audience1"},
			cachedToken:    "expired-token",
			cachedExpiry:   time.Now().Add(-1 * time.Hour),
			expectCacheHit: false,
			fetchResponse: &delegatedapi.FetchJWTSVIDsResponse{
				Svids: []*typesapi.JWTSVID{
					{
						Token:     "new-token",
						ExpiresAt: time.Now().Add(2 * time.Hour).Unix(),
					},
				},
			},
			expectError: false,
		},
		{
			name:        "fetch error",
			spiffeID:    "spiffe://example.org/test",
			audiences:   []string{"audience1"},
			fetchError:  errors.New("fetch failed"),
			expectError: true,
			errorMsg:    "failed to fetch JWT-SVID",
		},
		{
			name:      "empty response",
			spiffeID:  "spiffe://example.org/test",
			audiences: []string{"audience1"},
			fetchResponse: &delegatedapi.FetchJWTSVIDsResponse{
				Svids: []*typesapi.JWTSVID{},
			},
			expectError: true,
			errorMsg:    "no JWT-SVIDs returned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			config := Config{
				SpireSocketPath:   "/run/spire/socket",
				SpiffeTrustDomain: "example.org",
			}

			client, _ := New(logger, config)
			ctx := context.Background()

			// Setup cached entry if specified
			if tt.cachedToken != "" {
				cacheKey := client.jwtCache.createCacheKey(tt.spiffeID, tt.audiences)
				client.jwtCache.cache[cacheKey] = &jwtCacheEntry{
					token:     tt.cachedToken,
					expiresAt: tt.cachedExpiry,
					audiences: tt.audiences,
				}
			}

			// Mock the stream manager to be healthy
			client.streamManager.initialized.Store(true)
			client.streamManager.streamsHealthy.Store(true)

			// Setup mock delegated client
			mockClient := NewMockDelegatedIdentityClient(ctrl)
			client.conn.client = mockClient

			if !tt.expectCacheHit && tt.fetchResponse != nil {
				mockClient.EXPECT().
					FetchJWTSVIDs(gomock.Any(), gomock.Any()).
					Return(tt.fetchResponse, tt.fetchError)
			} else if !tt.expectCacheHit && tt.fetchError != nil {
				mockClient.EXPECT().
					FetchJWTSVIDs(gomock.Any(), gomock.Any()).
					Return(nil, tt.fetchError)
			}

			token, err := client.FetchJWTSVID(ctx, tt.spiffeID, tt.audiences)

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
				if tt.expectCacheHit && token != tt.cachedToken {
					t.Errorf("Expected cached token %q, got %q", tt.cachedToken, token)
				}
				if !tt.expectCacheHit && tt.fetchResponse != nil && token != tt.fetchResponse.Svids[0].Token {
					t.Errorf("Expected fetched token %q, got %q", tt.fetchResponse.Svids[0].Token, token)
				}
			}
		})
	}
}

func TestClient_Status(t *testing.T) {
	tests := []struct {
		name             string
		connected        bool
		lastConnectError error
		expectedStatus   bool
		expectedMsg      string
	}{
		{
			name:           "connected",
			connected:      true,
			expectedStatus: true,
			expectedMsg:    "Connected to SPIRE server",
		},
		{
			name:           "not connected",
			connected:      false,
			expectedStatus: false,
			expectedMsg:    "Not connected to SPIRE server",
		},
		{
			name:             "not connected with error",
			connected:        false,
			lastConnectError: errors.New("connection refused"),
			expectedStatus:   false,
			expectedMsg:      "Cannot connect to SPIRE server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			config := Config{
				SpireSocketPath:   "/run/spire/socket",
				SpiffeTrustDomain: "example.org",
			}

			client, _ := New(logger, config)
			client.conn.connected = tt.connected
			client.conn.lastConnectError = tt.lastConnectError

			status, msg := client.Status()

			if status != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, status)
			}
			if !contains(msg, tt.expectedMsg) {
				t.Errorf("Expected message containing %q, got %q", tt.expectedMsg, msg)
			}
		})
	}
}

func TestClient_ConcurrentOperations(t *testing.T) {
	logger := hclog.NewNullLogger()
	config := Config{
		SpireSocketPath:   "/run/spire/socket",
		SpiffeTrustDomain: "example.org",
	}

	client, _ := New(logger, config)
	ctx := context.Background()

	// Setup some initial data
	cert := generateTestCACertificate(t)
	client.bundleManager.parsedCerts["example.org"] = []*x509.Certificate{cert}

	svid := createTestSVID("example.org", "/test")
	client.svidManager.store["spiffe://example.org/test"] = svid

	// Mock the stream manager to be healthy
	client.streamManager.initialized.Store(true)
	client.streamManager.streamsHealthy.Store(true)

	// Run concurrent operations
	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client.GetCACertificates(ctx)
			client.GetCertificateForIdentity("spiffe://example.org/test")
			client.Status()
			client.GetTrustBundle()
		}()
	}

	// Concurrent updates through managers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			svids := []*delegatedapi.X509SVIDWithKey{
				createTestSVID("example.org", fmt.Sprintf("/test%d", id)),
			}
			client.svidManager.handleUpdate(svids, "example.org")
		}(i)
	}

	wg.Wait()

	// Verify client is still in valid state
	if client.svidManager.store == nil {
		t.Error("SVID store should not be nil after concurrent operations")
	}
	if client.bundleManager.parsedCerts == nil {
		t.Error("Parsed certs should not be nil after concurrent operations")
	}
}

// Helper functions

func generateTestCACertificate(t *testing.T) *x509.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func generateTestCertificate(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert, key
}

func createTestSVID(trustDomain, path string) *delegatedapi.X509SVIDWithKey {
	cert, key := generateTestCertificate(nil)
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

func TestClient_StopCallsSVIDManagerCleanup(t *testing.T) {
	logger := hclog.NewNullLogger()
	config := Config{
		SpireSocketPath:   "/run/spire/socket",
		SpiffeTrustDomain: "example.org",
	}

	client, err := New(logger, config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	originalCtx := client.svidManager.cleanupCtx

	err = client.Stop()
	if err != nil {
		t.Errorf("Stop() returned error: %v", err)
	}

	select {
	case <-originalCtx.Done():
	default:
		t.Error("SVID manager cleanup should have been called during Stop()")
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
