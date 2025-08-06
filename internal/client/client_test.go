package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/golang/mock/gomock"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

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
				// Preload SVID in store
				client.svidStore[tt.spiffeID] = &delegatedapi.X509SVIDWithKey{
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
					client.svidStoreMutex.Lock()
					client.svidStore[tt.spiffeID] = &delegatedapi.X509SVIDWithKey{
						X509Svid: &typesapi.X509SVID{
							Id: &typesapi.SPIFFEID{
								TrustDomain: "example.org",
								Path:        "/test",
							},
							ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
						},
					}
					client.svidStoreMutex.Unlock()

					// Notify waiter
					client.svidWaitersMutex.Lock()
					if waitChan, exists := client.svidWaiters[tt.spiffeID]; exists {
						close(waitChan)
						delete(client.svidWaiters, tt.spiffeID)
					}
					client.svidWaitersMutex.Unlock()
				}()
			}

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
				// Preload trust bundle
				cert := generateTestCACertificate(t)
				client.parsedCerts["example.org"] = []*x509.Certificate{cert}
			}

			if tt.simulateUpdate {
				// Simulate bundle becoming available after a delay
				go func() {
					time.Sleep(100 * time.Millisecond)
					cert := generateTestCACertificate(t)
					client.parsedCertsMutex.Lock()
					client.parsedCerts["example.org"] = []*x509.Certificate{cert}
					client.parsedCertsMutex.Unlock()

					// Signal bundle ready
					client.trustBundleOnce.Do(func() {
						client.trustBundleReady = make(chan struct{})
					})
					select {
					case <-client.trustBundleReady:
					default:
						close(client.trustBundleReady)
					}
				}()
			}

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
			client.parsedCerts = tt.setupCerts

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

				client.svidStore[tt.spiffeID] = svid
			}

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
		{
			name:        "nil delegated client",
			spiffeID:    "spiffe://example.org/test",
			audiences:   []string{"audience1"},
			expectError: true,
			errorMsg:    "not connected to SPIRE",
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
				cacheKey := client.createJWTCacheKey(tt.spiffeID, tt.audiences)
				client.jwtSVIDCache[cacheKey] = &jwtCacheEntry{
					token:     tt.cachedToken,
					expiresAt: tt.cachedExpiry,
					audiences: tt.audiences,
				}
			}

			// Setup mock delegated client if not testing nil client
			if tt.name != "nil delegated client" {
				mockClient := NewMockDelegatedIdentityClient(ctrl)
				client.delegatedIdentityClient = mockClient

				if !tt.expectCacheHit && tt.fetchResponse != nil {
					mockClient.EXPECT().
						FetchJWTSVIDs(gomock.Any(), gomock.Any()).
						Return(tt.fetchResponse, tt.fetchError)
				} else if !tt.expectCacheHit && tt.fetchError != nil {
					mockClient.EXPECT().
						FetchJWTSVIDs(gomock.Any(), gomock.Any()).
						Return(nil, tt.fetchError)
				}
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

func TestClient_HandleX509SVIDUpdate(t *testing.T) {
	tests := []struct {
		name                string
		existingSVIDs       map[string]*delegatedapi.X509SVIDWithKey
		updateSVIDs         []*delegatedapi.X509SVIDWithKey
		expectedStore       int
		trustDomainMismatch bool
	}{
		{
			name:          "new SVID added",
			existingSVIDs: map[string]*delegatedapi.X509SVIDWithKey{},
			updateSVIDs: []*delegatedapi.X509SVIDWithKey{
				createTestSVID("example.org", "/test"),
			},
			expectedStore: 1,
		},
		{
			name: "existing SVID updated",
			existingSVIDs: map[string]*delegatedapi.X509SVIDWithKey{
				"spiffe://example.org/test": createTestSVID("example.org", "/test"),
			},
			updateSVIDs: []*delegatedapi.X509SVIDWithKey{
				createTestSVIDWithExpiry("example.org", "/test", time.Now().Add(2*time.Hour)),
			},
			expectedStore: 1,
		},
		{
			name: "SVID deleted",
			existingSVIDs: map[string]*delegatedapi.X509SVIDWithKey{
				"spiffe://example.org/test":  createTestSVID("example.org", "/test"),
				"spiffe://example.org/test2": createTestSVID("example.org", "/test2"),
			},
			updateSVIDs: []*delegatedapi.X509SVIDWithKey{
				createTestSVID("example.org", "/test"),
			},
			expectedStore: 1,
		},
		{
			name:          "trust domain mismatch",
			existingSVIDs: map[string]*delegatedapi.X509SVIDWithKey{},
			updateSVIDs: []*delegatedapi.X509SVIDWithKey{
				createTestSVID("other.org", "/test"),
			},
			trustDomainMismatch: true,
			expectedStore:       0,
		},
		{
			name:          "multiple SVIDs",
			existingSVIDs: map[string]*delegatedapi.X509SVIDWithKey{},
			updateSVIDs: []*delegatedapi.X509SVIDWithKey{
				createTestSVID("example.org", "/test1"),
				createTestSVID("example.org", "/test2"),
				createTestSVID("example.org", "/test3"),
			},
			expectedStore: 3,
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
			client.svidStore = tt.existingSVIDs
			client.svidWaiters = make(map[string]chan struct{})

			// Handle update
			client.handleX509SVIDUpdate(tt.updateSVIDs)

			// Verify store
			if !tt.trustDomainMismatch {
				if len(client.svidStore) != tt.expectedStore {
					t.Errorf("Expected %d SVIDs in store, got %d", tt.expectedStore, len(client.svidStore))
				}
			} else {
				// For trust domain mismatch, store should remain unchanged
				if len(client.svidStore) != len(tt.existingSVIDs) {
					t.Error("Store should not change for trust domain mismatch")
				}
			}
		})
	}
}

func TestClient_HandleX509BundleUpdate(t *testing.T) {
	tests := []struct {
		name            string
		bundles         map[string][]byte
		expectError     bool
		expectedDomains int
		expectedCerts   map[string]int
	}{
		{
			name: "single domain bundle",
			bundles: map[string][]byte{
				"example.org": generateTestCACertificate(t).Raw,
			},
			expectedDomains: 1,
			expectedCerts: map[string]int{
				"example.org": 1,
			},
		},
		{
			name: "multiple domain bundles",
			bundles: map[string][]byte{
				"example.org": generateTestCACertificate(t).Raw,
				"test.org":    generateTestCACertificate(t).Raw,
			},
			expectedDomains: 2,
			expectedCerts: map[string]int{
				"example.org": 1,
				"test.org":    1,
			},
		},
		{
			name: "invalid certificate",
			bundles: map[string][]byte{
				"example.org": []byte("invalid-cert"),
			},
			expectedDomains: 0,
			expectError:     true,
		},
		{
			name:            "empty bundles",
			bundles:         map[string][]byte{},
			expectedDomains: 0,
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

			// Handle update
			client.handleX509BundleUpdate(tt.bundles)

			// Verify parsed certs
			if len(client.parsedCerts) != tt.expectedDomains {
				t.Errorf("Expected %d domains, got %d", tt.expectedDomains, len(client.parsedCerts))
			}

			for domain, expectedCount := range tt.expectedCerts {
				if certs, exists := client.parsedCerts[domain]; exists {
					if len(certs) != expectedCount {
						t.Errorf("Domain %s: expected %d certs, got %d", domain, expectedCount, len(certs))
					}
				} else {
					t.Errorf("Expected domain %s not found", domain)
				}
			}

			// Verify trust bundle is set
			if !tt.expectError && client.trustBundle == nil {
				t.Error("Trust bundle should be set")
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
			client.connected = tt.connected
			client.lastConnectError = tt.lastConnectError

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
	client.parsedCerts["example.org"] = []*x509.Certificate{cert}

	svid := createTestSVID("example.org", "/test")
	client.svidStore["spiffe://example.org/test"] = svid

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

	// Concurrent updates
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			svids := []*delegatedapi.X509SVIDWithKey{
				createTestSVID("example.org", fmt.Sprintf("/test%d", id)),
			}
			client.handleX509SVIDUpdate(svids)
		}(i)
	}

	wg.Wait()

	// Verify client is still in valid state
	if client.svidStore == nil {
		t.Error("SVID store should not be nil after concurrent operations")
	}
	if client.parsedCerts == nil {
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

func createTestSVIDWithExpiry(trustDomain, path string, expiry time.Time) *delegatedapi.X509SVIDWithKey {
	svid := createTestSVID(trustDomain, path)
	svid.X509Svid.ExpiresAt = expiry.Unix()
	return svid
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (strings.Contains(s, substr))
}
