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
)

func TestNewTrustBundleManager(t *testing.T) {
	logger := hclog.NewNullLogger()
	tbm := newTrustBundleManager(logger)

	if tbm == nil {
		t.Fatal("Expected non-nil trust bundle manager")
	}
	if tbm.logger == nil {
		t.Error("Logger should be set")
	}
	if tbm.parsedCerts == nil {
		t.Error("ParsedCerts should be initialized")
	}
}

func TestTrustBundleManager_WaitForBundle(t *testing.T) {
	tests := []struct {
		name           string
		timeout        time.Duration
		preloadBundle  bool
		simulateUpdate bool
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
			timeout:        1 * time.Second,
			simulateUpdate: true,
			expectError:    false,
		},
		{
			name:        "timeout waiting for bundle",
			timeout:     100 * time.Millisecond,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			tbm := newTrustBundleManager(logger)
			ctx := context.Background()

			if tt.preloadBundle {
				cert := generateTestCACert()
				tbm.parsedCerts["example.org"] = []*x509.Certificate{cert}
			}

			if tt.simulateUpdate {
				go func() {
					time.Sleep(50 * time.Millisecond)
					bundles := map[string][]byte{
						"example.org": generateTestCACert().Raw,
					}
					tbm.handleUpdate(bundles)
				}()
			}

			err := tbm.waitForBundle(ctx, tt.timeout)

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

func TestTrustBundleManager_HandleUpdate(t *testing.T) {
	tests := []struct {
		name            string
		bundles         map[string][]byte
		expectedDomains int
		expectedCerts   map[string]int
		expectError     bool
	}{
		{
			name: "single domain bundle",
			bundles: map[string][]byte{
				"example.org": generateTestCACert().Raw,
			},
			expectedDomains: 1,
			expectedCerts: map[string]int{
				"example.org": 1,
			},
		},
		{
			name: "multiple domain bundles",
			bundles: map[string][]byte{
				"example.org": generateTestCACert().Raw,
				"test.org":    generateTestCACert().Raw,
				"prod.org":    generateTestCACert().Raw,
			},
			expectedDomains: 3,
			expectedCerts: map[string]int{
				"example.org": 1,
				"test.org":    1,
				"prod.org":    1,
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
			name: "mixed valid and invalid",
			bundles: map[string][]byte{
				"example.org": generateTestCACert().Raw,
				"invalid.org": []byte("invalid-cert"),
				"test.org":    generateTestCACert().Raw,
			},
			expectedDomains: 2,
			expectedCerts: map[string]int{
				"example.org": 1,
				"test.org":    1,
			},
		},
		{
			name:            "empty bundles",
			bundles:         map[string][]byte{},
			expectedDomains: 0,
		},
		{
			name: "multiple certs in bundle",
			bundles: map[string][]byte{
				"example.org": combineCerts(
					generateTestCACert(),
					generateTestCACert(),
					generateTestCACert(),
				),
			},
			expectedDomains: 1,
			expectedCerts: map[string]int{
				"example.org": 3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			tbm := newTrustBundleManager(logger)

			tbm.handleUpdate(tt.bundles)

			if len(tbm.parsedCerts) != tt.expectedDomains {
				t.Errorf("Expected %d domains, got %d", tt.expectedDomains, len(tbm.parsedCerts))
			}

			for domain, expectedCount := range tt.expectedCerts {
				if certs, exists := tbm.parsedCerts[domain]; exists {
					if len(certs) != expectedCount {
						t.Errorf("Domain %s: expected %d certs, got %d", domain, expectedCount, len(certs))
					}
				} else {
					t.Errorf("Expected domain %s not found", domain)
				}
			}

			// Verify trust bundle is set
			if !tt.expectError && tt.expectedDomains > 0 && tbm.trustBundle == nil {
				t.Error("Trust bundle should be set")
			}
		})
	}
}

func TestTrustBundleManager_GetCACertificates(t *testing.T) {
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
					generateTestCACert(),
					generateTestCACert(),
				},
			},
			expectError:   false,
			expectedCount: 2,
		},
		{
			name: "multiple trust domains",
			setupCerts: map[string][]*x509.Certificate{
				"example.org": {
					generateTestCACert(),
				},
				"test.org": {
					generateTestCACert(),
					generateTestCACert(),
				},
				"prod.org": {
					generateTestCACert(),
				},
			},
			expectError:   false,
			expectedCount: 4,
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
			tbm := newTrustBundleManager(logger)
			tbm.parsedCerts = tt.setupCerts

			certs, err := tbm.getCACertificates()

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

func TestTrustBundleManager_GetTrustBundle(t *testing.T) {
	tests := []struct {
		name        string
		setupBundle bool
		expectError bool
	}{
		{
			name:        "bundle available",
			setupBundle: true,
			expectError: false,
		},
		{
			name:        "bundle not available",
			setupBundle: false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			tbm := newTrustBundleManager(logger)

			if tt.setupBundle {
				pool := x509.NewCertPool()
				pool.AddCert(generateTestCACert())
				tbm.trustBundle = pool
			}

			bundle, err := tbm.getTrustBundle()

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if bundle == nil {
					t.Error("Expected trust bundle but got nil")
				}
			}
		})
	}
}

func TestTrustBundleManager_ConcurrentAccess(t *testing.T) {
	logger := hclog.NewNullLogger()
	tbm := newTrustBundleManager(logger)

	tbm.parsedCerts["example.org"] = []*x509.Certificate{generateTestCACert()}

	done := make(chan bool, 100)

	// Concurrent reads
	for i := 0; i < 25; i++ {
		go func() {
			tbm.getCACertificates()
			done <- true
		}()
	}

	for i := 0; i < 25; i++ {
		go func() {
			tbm.getTrustBundle()
			done <- true
		}()
	}

	// Concurrent updates
	for i := 0; i < 25; i++ {
		go func(id int) {
			bundles := map[string][]byte{
				fmt.Sprintf("domain%d.org", id): generateTestCACert().Raw,
			}
			tbm.handleUpdate(bundles)
			done <- true
		}(i)
	}

	// Concurrent waits
	for i := 0; i < 25; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			tbm.waitForBundle(ctx, 50*time.Millisecond)
			done <- true
		}()
	}

	// Wait for all operations
	for i := 0; i < 100; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}
}

func TestTrustBundleManager_ReadySignal(t *testing.T) {
	logger := hclog.NewNullLogger()
	tbm := newTrustBundleManager(logger)

	// First update should signal ready
	bundles1 := map[string][]byte{
		"example.org": generateTestCACert().Raw,
	}
	tbm.handleUpdate(bundles1)

	// Start waiting after first update
	ctx := context.Background()
	err := tbm.waitForBundle(ctx, 100*time.Millisecond)
	if err != nil {
		t.Error("Should not timeout after bundle is ready")
	}

	// Second update should not cause issues
	bundles2 := map[string][]byte{
		"test.org": generateTestCACert().Raw,
	}
	tbm.handleUpdate(bundles2)

	// Should still be ready
	err = tbm.waitForBundle(ctx, 100*time.Millisecond)
	if err != nil {
		t.Error("Should still be ready after second update")
	}
}

func generateTestCACert() *x509.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			Country:      []string{"US"},
			CommonName:   "Test CA Root",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

func combineCerts(certs ...*x509.Certificate) []byte {
	var combined []byte
	for _, cert := range certs {
		combined = append(combined, cert.Raw...)
	}
	return combined
}
