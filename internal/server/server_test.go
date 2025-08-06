package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"spire-csi-provider/internal/client"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/go-hclog"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
	"spire-csi-provider/internal/config"
	"spire-csi-provider/internal/hmac"
	"spire-csi-provider/internal/version"
)

func TestNewServer(t *testing.T) {
	tests := []struct {
		name        string
		logger      hclog.Logger
		flagsConfig config.FlagsConfig
		hmacGen     *hmac.HMACGenerator
		wantPanic   bool
	}{
		{
			name:   "valid configuration",
			logger: hclog.NewNullLogger(),
			flagsConfig: config.FlagsConfig{
				ProviderStaleTimeout:    10 * time.Minute,
				ProviderCleanupInterval: 5 * time.Minute,
				SpireSocketPath:         "/socket",
			},
			hmacGen:   hmac.NewHMACGenerator([]byte("test-key")),
			wantPanic: false,
		},
		{
			name:   "nil logger should panic",
			logger: nil,
			flagsConfig: config.FlagsConfig{
				ProviderStaleTimeout:    10 * time.Minute,
				ProviderCleanupInterval: 5 * time.Minute,
			},
			hmacGen:   hmac.NewHMACGenerator([]byte("test-key")),
			wantPanic: true,
		},
		{
			name:   "nil hmac generator",
			logger: hclog.NewNullLogger(),
			flagsConfig: config.FlagsConfig{
				ProviderStaleTimeout:    10 * time.Minute,
				ProviderCleanupInterval: 5 * time.Minute,
			},
			hmacGen:   nil,
			wantPanic: false,
		},
		{
			name:   "zero timeouts",
			logger: hclog.NewNullLogger(),
			flagsConfig: config.FlagsConfig{
				ProviderStaleTimeout:    0,
				ProviderCleanupInterval: 0,
			},
			hmacGen:   hmac.NewHMACGenerator([]byte("test-key")),
			wantPanic: false,
		},
		{
			name:   "dual agent mode",
			logger: hclog.NewNullLogger(),
			flagsConfig: config.FlagsConfig{
				SpireSocketPath:         "/socket1",
				SpireSocketPath2:        "/socket2",
				ProviderStaleTimeout:    10 * time.Minute,
				ProviderCleanupInterval: 5 * time.Minute,
			},
			hmacGen:   hmac.NewHMACGenerator([]byte("test-key")),
			wantPanic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Error("Expected panic but didn't get one")
					}
				}()
			}

			server := NewServer(tt.logger, tt.flagsConfig, tt.hmacGen)

			if tt.wantPanic {
				t.Error("Should have panicked but didn't")
				return
			}

			if server == nil {
				t.Error("Expected non-nil server")
				return
			}

			if server.logger == nil && tt.logger != nil {
				t.Error("Logger not set correctly")
			}
			if server.hmacGenerator != tt.hmacGen {
				t.Error("HMAC generator not set correctly")
			}
			if server.clientPool == nil {
				t.Error("Client pool should be initialized")
			}
			if server.flagsConfig.SpireSocketPath != tt.flagsConfig.SpireSocketPath {
				t.Error("Socket path not set correctly")
			}
			if server.flagsConfig.SpireSocketPath2 != tt.flagsConfig.SpireSocketPath2 {
				t.Error("Socket path 2 not set correctly")
			}
		})
	}
}

func TestServer_Version(t *testing.T) {
	tests := []struct {
		name           string
		buildVersion   string
		driverVersion  string
		expectedRT     string
		expectedRTName string
	}{
		{
			name:           "standard version",
			buildVersion:   "v1.2.3",
			driverVersion:  "v0.0.1",
			expectedRT:     "v1.2.3",
			expectedRTName: "spire-csi-provider",
		},
		{
			name:           "development version",
			buildVersion:   "dev",
			driverVersion:  "v0.0.2",
			expectedRT:     "dev",
			expectedRTName: "spire-csi-provider",
		},
		{
			name:           "empty version",
			buildVersion:   "",
			driverVersion:  "",
			expectedRT:     "",
			expectedRTName: "spire-csi-provider",
		},
		{
			name:           "semantic version",
			buildVersion:   "v2.0.0-rc1",
			driverVersion:  "v1.0.0",
			expectedRT:     "v2.0.0-rc1",
			expectedRTName: "spire-csi-provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			flagsConfig := config.FlagsConfig{}
			hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
			server := NewServer(logger, flagsConfig, hmacGen)

			// Set version for testing
			version.BuildVersion = tt.buildVersion

			req := &pb.VersionRequest{
				Version: tt.driverVersion,
			}

			ctx := context.Background()
			resp, err := server.Version(ctx, req)

			if err != nil {
				t.Fatalf("Version() error = %v", err)
			}

			if resp.Version != "v1alpha1" {
				t.Errorf("Expected API version v1alpha1, got %s", resp.Version)
			}
			if resp.RuntimeName != tt.expectedRTName {
				t.Errorf("Expected runtime name %s, got %s", tt.expectedRTName, resp.RuntimeName)
			}
			if resp.RuntimeVersion != tt.expectedRT {
				t.Errorf("Expected runtime version %s, got %s", tt.expectedRT, resp.RuntimeVersion)
			}
		})
	}
}

func TestServer_Mount_VariousConfigurations(t *testing.T) {
	tests := []struct {
		name            string
		attributes      map[string]string
		permission      string
		targetPath      string
		currentVersions []*pb.ObjectVersion
		setupMock       func(*gomock.Controller) *client.MockClientPoolInterface
		expectFiles     int
		expectVersions  int
		expectError     bool
		errorContains   string
	}{
		{
			name: "successful JWT mount",
			attributes: map[string]string{
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"trustDomain":                            "example.org",
				"objects": `
- objectName: test-jwt
  type: jwt-svid
  audience:
    - audience1
  paths:
    - /token.jwt`,
			},
			permission: "420",
			targetPath: "/var/run/secrets",
			setupMock: func(ctrl *gomock.Controller) *client.MockClientPoolInterface {
				mockClient := client.NewMockSpireClient(ctrl)
				mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil)
				mockClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return("test-jwt-token", nil)

				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()
				mockPool.EXPECT().GetPoolStats().Return(map[string]interface{}{
					"total_clients":  1,
					"active_clients": 1,
					"total_refs":     1,
				})
				return mockPool
			},
			expectFiles:    1,
			expectVersions: 1,
			expectError:    false,
		},
		{
			name: "successful X509 mount",
			attributes: map[string]string{
				"csi.storage.k8s.io/pod.namespace":       "production",
				"csi.storage.k8s.io/pod.name":            "prod-pod",
				"csi.storage.k8s.io/pod.uid":             "789-012",
				"csi.storage.k8s.io/serviceAccount.name": "prod-sa",
				"trustDomain":                            "prod.example.org",
				"objects": `
- objectName: x509-cert
  type: x509-svid
  paths:
    - /tls/cert.pem
    - /tls/key.pem
    - /tls/ca.pem`,
			},
			permission: "384", // 0600
			targetPath: "/var/run/tls",
			setupMock: func(ctrl *gomock.Controller) *client.MockClientPoolInterface {
				mockClient := client.NewMockSpireClient(ctrl)
				mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil)

				// For X509, we need certificate and CA certs
				cert, key := generateTestCertAndKey()
				mockClient.EXPECT().GetCertificateForIdentity(gomock.Any()).Return(&tls.Certificate{
					Certificate: [][]byte{cert},
					PrivateKey:  key,
				}, nil)
				mockClient.EXPECT().GetCACertificates(gomock.Any()).Return([]*x509.Certificate{
					generateTestCA(),
				}, nil)

				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()
				mockPool.EXPECT().GetPoolStats().Return(map[string]interface{}{
					"total_clients": 1,
				})
				return mockPool
			},
			expectFiles:    3,
			expectVersions: 1,
			expectError:    false,
		},
		{
			name: "multiple objects",
			attributes: map[string]string{
				"csi.storage.k8s.io/pod.namespace":       "staging",
				"csi.storage.k8s.io/pod.name":            "multi-pod",
				"csi.storage.k8s.io/pod.uid":             "multi-123",
				"csi.storage.k8s.io/serviceAccount.name": "multi-sa",
				"trustDomain":                            "staging.example.org",
				"objects": `
- objectName: jwt-token
  type: jwt-svid
  audience:
    - api.staging
  paths:
    - /tokens/api.jwt
- objectName: x509-cert
  type: x509-svid
  paths:
    - /certs/cert.pem
    - /certs/key.pem
    - /certs/bundle.pem`,
			},
			permission: "420",
			targetPath: "/var/run/secrets",
			setupMock: func(ctrl *gomock.Controller) *client.MockClientPoolInterface {
				mockClient := client.NewMockSpireClient(ctrl)
				mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil)
				mockClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return("staging-jwt", nil)

				cert, key := generateTestCertAndKey()
				mockClient.EXPECT().GetCertificateForIdentity(gomock.Any()).Return(&tls.Certificate{
					Certificate: [][]byte{cert},
					PrivateKey:  key,
				}, nil)
				mockClient.EXPECT().GetCACertificates(gomock.Any()).Return([]*x509.Certificate{
					generateTestCA(),
				}, nil)

				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()
				mockPool.EXPECT().GetPoolStats().Return(map[string]interface{}{
					"total_clients": 2,
				})
				return mockPool
			},
			expectFiles:    4,
			expectVersions: 2,
			expectError:    false,
		},
		{
			name: "with current object versions",
			attributes: map[string]string{
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"trustDomain":                            "example.org",
				"objects": `
- objectName: test-jwt
  type: jwt-svid
  audience:
    - audience1
  paths:
    - /token.jwt`,
			},
			permission: "420",
			targetPath: "/var/run/secrets",
			currentVersions: []*pb.ObjectVersion{
				{
					Id:      "test-jwt",
					Version: "old-version-123",
				},
			},
			setupMock: func(ctrl *gomock.Controller) *client.MockClientPoolInterface {
				mockClient := client.NewMockSpireClient(ctrl)
				mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil)
				mockClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return("new-jwt-token", nil)

				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()
				mockPool.EXPECT().GetPoolStats().Return(map[string]interface{}{
					"total_clients": 1,
				})
				return mockPool
			},
			expectFiles:    1,
			expectVersions: 1,
			expectError:    false,
		},
		{
			name: "kube-system namespace",
			attributes: map[string]string{
				"csi.storage.k8s.io/pod.namespace":       "kube-system",
				"csi.storage.k8s.io/pod.name":            "system-pod",
				"csi.storage.k8s.io/pod.uid":             "sys-123",
				"csi.storage.k8s.io/serviceAccount.name": "system-sa",
				"trustDomain":                            "cluster.local",
				"objects": `
- objectName: system-jwt
  type: jwt-svid
  audience:
    - kube-apiserver
  paths:
    - /system/token.jwt`,
			},
			permission: "256", // 0400
			targetPath: "/var/run/system",
			setupMock: func(ctrl *gomock.Controller) *client.MockClientPoolInterface {
				mockClient := client.NewMockSpireClient(ctrl)
				mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil)
				mockClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), []string{"kube-apiserver"}).Return("system-jwt", nil)

				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()
				mockPool.EXPECT().GetPoolStats().Return(map[string]interface{}{
					"total_clients": 1,
				})
				return mockPool
			},
			expectFiles:    1,
			expectVersions: 1,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			flagsConfig := config.FlagsConfig{
				SpireSocketPath: "/run/spire/socket",
			}
			hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
			server := NewServer(logger, flagsConfig, hmacGen)

			attributesJSON, _ := json.Marshal(tt.attributes)

			req := &pb.MountRequest{
				Attributes:           string(attributesJSON),
				TargetPath:           tt.targetPath,
				Permission:           tt.permission,
				Secrets:              "{}",
				CurrentObjectVersion: tt.currentVersions,
			}

			server.clientPool = tt.setupMock(ctrl)

			ctx := context.Background()
			resp, err := server.Mount(ctx, req)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("Error should contain %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Mount() error = %v", err)
				}

				if resp == nil {
					t.Fatal("Expected non-nil response")
				}

				if len(resp.Files) != tt.expectFiles {
					t.Errorf("Expected %d files, got %d", tt.expectFiles, len(resp.Files))
				}
				if len(resp.ObjectVersion) != tt.expectVersions {
					t.Errorf("Expected %d object versions, got %d", tt.expectVersions, len(resp.ObjectVersion))
				}
			}
		})
	}
}

// internal/server/server_test.go - Fixed version

func TestServer_Mount_ErrorCases(t *testing.T) {
	tests := []struct {
		name          string
		attributes    string
		permission    string
		targetPath    string
		setupMock     func(*gomock.Controller) *client.MockClientPoolInterface
		errorContains string
	}{
		{
			name:          "invalid JSON attributes",
			attributes:    "not-valid-json{",
			permission:    "420",
			targetPath:    "/var/run/secrets",
			setupMock:     nil,
			errorContains: "error parsing configuration",
		},
		{
			name:          "invalid permission format",
			attributes:    `{"trustDomain":"example.org"}`,
			permission:    "not-a-number",
			targetPath:    "/var/run/secrets",
			setupMock:     nil,
			errorContains: "error parsing configuration",
		},
		{
			name:          "empty attributes",
			attributes:    "",
			permission:    "420",
			targetPath:    "/var/run/secrets",
			setupMock:     nil,
			errorContains: "error parsing configuration",
		},
		{
			name: "missing pod info - no namespace",
			attributes: func() string {
				attrs := map[string]string{
					// Missing csi.storage.k8s.io/pod.namespace
					"csi.storage.k8s.io/pod.name":            "test-pod",
					"csi.storage.k8s.io/pod.uid":             "123",
					"csi.storage.k8s.io/serviceAccount.name": "test-sa",
					"trustDomain":                            "example.org",
					"objects": `
- objectName: test
  type: jwt-svid
  audience: ["test"]
  paths: ["/token"]`,
				}
				data, _ := json.Marshal(attrs)
				return string(data)
			}(),
			permission: "420",
			targetPath: "/var/run/secrets",
			setupMock: func(ctrl *gomock.Controller) *client.MockClientPoolInterface {
				// Even with missing namespace, the config might pass parsing
				// but we should fail fast at the provider level
				mockClient := client.NewMockSpireClient(ctrl)
				mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("invalid SPIFFE ID")).MaxTimes(1)

				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil).MaxTimes(1)
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return().MaxTimes(1)
				return mockPool
			},
			errorContains: "error handling mount request",
		},
		{
			name: "completely missing pod info fields",
			attributes: func() string {
				attrs := map[string]string{
					"trustDomain": "example.org",
					"objects": `
- objectName: test
  type: jwt-svid
  audience: ["test"]
  paths: ["/token"]`,
				}
				data, _ := json.Marshal(attrs)
				return string(data)
			}(),
			permission: "420",
			targetPath: "/var/run/secrets",
			setupMock: func(ctrl *gomock.Controller) *client.MockClientPoolInterface {
				// With completely missing pod info, it should build an empty SPIFFE ID
				// and fail immediately
				mockClient := client.NewMockSpireClient(ctrl)
				mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("empty SPIFFE ID")).MaxTimes(1)

				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil).MaxTimes(1)
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return().MaxTimes(1)
				return mockPool
			},
			errorContains: "error handling mount request",
		},
		{
			name: "no objects configured",
			attributes: func() string {
				attrs := map[string]string{
					"csi.storage.k8s.io/pod.namespace":       "default",
					"csi.storage.k8s.io/pod.name":            "test-pod",
					"csi.storage.k8s.io/pod.uid":             "123",
					"csi.storage.k8s.io/serviceAccount.name": "test-sa",
					"trustDomain":                            "example.org",
					// No objects field
				}
				data, _ := json.Marshal(attrs)
				return string(data)
			}(),
			permission:    "420",
			targetPath:    "/var/run/secrets",
			setupMock:     nil,
			errorContains: "no objects configured",
		},
		{
			name: "invalid object type in YAML",
			attributes: func() string {
				attrs := map[string]string{
					"csi.storage.k8s.io/pod.namespace":       "default",
					"csi.storage.k8s.io/pod.name":            "test-pod",
					"csi.storage.k8s.io/pod.uid":             "123",
					"csi.storage.k8s.io/serviceAccount.name": "test-sa",
					"trustDomain":                            "example.org",
					"objects": `
- objectName: test
  type: invalid-type
  paths: ["/token"]`,
				}
				data, _ := json.Marshal(attrs)
				return string(data)
			}(),
			permission:    "420",
			targetPath:    "/var/run/secrets",
			setupMock:     nil,
			errorContains: "invalid type",
		},
		{
			name: "provider pool error",
			attributes: func() string {
				attrs := map[string]string{
					"csi.storage.k8s.io/pod.namespace":       "default",
					"csi.storage.k8s.io/pod.name":            "test-pod",
					"csi.storage.k8s.io/pod.uid":             "123",
					"csi.storage.k8s.io/serviceAccount.name": "test-sa",
					"trustDomain":                            "example.org",
					"objects": `
- objectName: test
  type: jwt-svid
  audience: ["test"]
  paths: ["/token"]`,
				}
				data, _ := json.Marshal(attrs)
				return string(data)
			}(),
			permission: "420",
			targetPath: "/var/run/secrets",
			setupMock: func(ctrl *gomock.Controller) *client.MockClientPoolInterface {
				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("pool error"))
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return().AnyTimes()
				return mockPool
			},
			errorContains: "error handling mount request",
		},
		{
			name: "missing target path",
			attributes: func() string {
				attrs := map[string]string{
					"csi.storage.k8s.io/pod.namespace":       "default",
					"csi.storage.k8s.io/pod.name":            "test-pod",
					"csi.storage.k8s.io/pod.uid":             "123",
					"csi.storage.k8s.io/serviceAccount.name": "test-sa",
					"trustDomain":                            "example.org",
					"objects": `
- objectName: test
  type: jwt-svid
  audience: ["test"]
  paths: ["/token"]`,
				}
				data, _ := json.Marshal(attrs)
				return string(data)
			}(),
			permission:    "420",
			targetPath:    "", // Empty target path
			setupMock:     nil,
			errorContains: "missing target path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			flagsConfig := config.FlagsConfig{
				SpireSocketPath: "/run/spire/socket",
			}
			hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
			server := NewServer(logger, flagsConfig, hmacGen)

			req := &pb.MountRequest{
				Attributes: tt.attributes,
				TargetPath: tt.targetPath,
				Permission: tt.permission,
				Secrets:    "{}",
			}

			if tt.setupMock != nil {
				server.clientPool = tt.setupMock(ctrl)
			}

			// Use a context with a shorter timeout to avoid waiting 30s
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			_, err := server.Mount(ctx, req)

			if err == nil {
				t.Fatal("Expected error but got none")
			}
			if !contains(err.Error(), tt.errorContains) {
				t.Errorf("Expected error containing %q, got %q", tt.errorContains, err.Error())
			}
		})
	}
}

func TestServer_Mount_ConcurrentRequests(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := hclog.NewNullLogger()
	flagsConfig := config.FlagsConfig{
		SpireSocketPath: "/run/spire/socket",
	}
	hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
	server := NewServer(logger, flagsConfig, hmacGen)

	// Setup mock that can handle concurrent calls
	mockClient := client.NewMockSpireClient(ctrl)
	mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return("concurrent-jwt", nil).AnyTimes()

	mockPool := client.NewMockClientPoolInterface(ctrl)
	mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil).AnyTimes()
	mockPool.EXPECT().ReleaseClient(gomock.Any()).Return().AnyTimes()
	mockPool.EXPECT().GetPoolStats().Return(map[string]interface{}{
		"total_clients":  1,
		"active_clients": 1,
	}).AnyTimes()

	server.clientPool = mockPool

	// Prepare request
	attributes := map[string]string{
		"csi.storage.k8s.io/pod.namespace":       "concurrent",
		"csi.storage.k8s.io/pod.name":            "concurrent-pod",
		"csi.storage.k8s.io/pod.uid":             "concurrent-123",
		"csi.storage.k8s.io/serviceAccount.name": "concurrent-sa",
		"trustDomain":                            "example.org",
		"objects": `
- objectName: jwt
  type: jwt-svid
  audience: ["test"]
  paths: ["/token.jwt"]`,
	}
	attributesJSON, _ := json.Marshal(attributes)

	// Run concurrent requests
	numRequests := 20
	var wg sync.WaitGroup
	errorsChan := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Create unique request for each goroutine
			req := &pb.MountRequest{
				Attributes: string(attributesJSON),
				TargetPath: fmt.Sprintf("/var/run/secrets/%d", id),
				Permission: "420",
				Secrets:    "{}",
			}

			ctx := context.Background()
			resp, err := server.Mount(ctx, req)
			if err != nil {
				errorsChan <- err
				return
			}
			if resp == nil || len(resp.Files) == 0 {
				errorsChan <- errors.New("invalid response")
			}
		}(i)
	}

	wg.Wait()
	close(errorsChan)

	// Check for errors
	var errorCount int
	for err := range errorsChan {
		t.Errorf("Concurrent request failed: %v", err)
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("%d out of %d concurrent requests failed", errorCount, numRequests)
	}
}

func TestServer_Shutdown(t *testing.T) {
	tests := []struct {
		name        string
		shutdownErr error
		expectError bool
	}{
		{
			name:        "successful shutdown",
			shutdownErr: nil,
			expectError: false,
		},
		{
			name:        "shutdown with error",
			shutdownErr: errors.New("shutdown failed"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			flagsConfig := config.FlagsConfig{}
			hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
			server := NewServer(logger, flagsConfig, hmacGen)

			// Create mock pool
			mockPool := client.NewMockClientPoolInterface(ctrl)
			mockPool.EXPECT().Shutdown().Return(tt.shutdownErr)

			server.clientPool = mockPool

			err := server.Shutdown()

			if (err != nil) != tt.expectError {
				t.Errorf("Shutdown() error = %v, expectError %v", err, tt.expectError)
			}
			if err != nil && tt.shutdownErr != nil && err.Error() != tt.shutdownErr.Error() {
				t.Errorf("Expected error %v, got %v", tt.shutdownErr, err)
			}
		})
	}
}

func TestHealthServer_Check(t *testing.T) {
	tests := []struct {
		name    string
		service string
		want    healthpb.HealthCheckResponse_ServingStatus
	}{
		{
			name:    "check default service",
			service: "",
			want:    healthpb.HealthCheckResponse_SERVING,
		},
		{
			name:    "check specific service",
			service: "spire-csi-provider",
			want:    healthpb.HealthCheckResponse_SERVING,
		},
		{
			name:    "check unknown service",
			service: "unknown-service",
			want:    healthpb.HealthCheckResponse_SERVING,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			hs := &healthServer{logger: logger}

			req := &healthpb.HealthCheckRequest{
				Service: tt.service,
			}

			ctx := context.Background()
			resp, err := hs.Check(ctx, req)

			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}

			if resp.Status != tt.want {
				t.Errorf("Expected status %v, got %v", tt.want, resp.Status)
			}
		})
	}
}

func TestHealthServer_Watch(t *testing.T) {
	logger := hclog.NewNullLogger()
	hs := &healthServer{logger: logger}

	req := &healthpb.HealthCheckRequest{
		Service: "test-service",
	}

	// Watch currently returns nil (not implemented)
	err := hs.Watch(req, nil)
	if err != nil {
		t.Errorf("Watch() error = %v", err)
	}
}

func TestGenerateRequestID(t *testing.T) {
	// Test uniqueness
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateRequestID()
		if id == "" {
			t.Error("Generated empty request ID")
		}
		if ids[id] {
			t.Errorf("Duplicate request ID generated: %s", id)
		}
		ids[id] = true
		time.Sleep(1 * time.Microsecond) // Ensure different timestamps
	}
}

func TestServer_Mount_MetricsLogging(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a custom logger to capture logs
	logger := hclog.NewNullLogger()
	flagsConfig := config.FlagsConfig{
		SpireSocketPath: "/run/spire/socket",
	}
	hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
	server := NewServer(logger, flagsConfig, hmacGen)

	// Setup successful mount
	mockClient := client.NewMockSpireClient(ctrl)
	mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil)
	mockClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return("metrics-jwt", nil)

	mockPool := client.NewMockClientPoolInterface(ctrl)
	mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
	mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()

	// Expect GetPoolStats to be called
	poolStats := map[string]interface{}{
		"total_clients":  5,
		"active_clients": 3,
		"total_refs":     10,
	}
	mockPool.EXPECT().GetPoolStats().Return(poolStats)

	server.clientPool = mockPool

	attributes := map[string]string{
		"csi.storage.k8s.io/pod.namespace":       "monitoring",
		"csi.storage.k8s.io/pod.name":            "metrics-collector",
		"csi.storage.k8s.io/pod.uid":             "metrics-123",
		"csi.storage.k8s.io/serviceAccount.name": "metrics-sa",
		"trustDomain":                            "metrics.example.org",
		"objects": `
- objectName: metrics-jwt
  type: jwt-svid
  audience: ["prometheus"]
  paths: ["/metrics/token.jwt"]`,
	}
	attributesJSON, _ := json.Marshal(attributes)

	req := &pb.MountRequest{
		Attributes: string(attributesJSON),
		TargetPath: "/var/run/metrics",
		Permission: "420",
		Secrets:    "{}",
	}

	ctx := context.Background()
	resp, err := server.Mount(ctx, req)

	if err != nil {
		t.Fatalf("Mount() error = %v", err)
	}

	// Verify response
	if len(resp.Files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(resp.Files))
	}

	// Verify that pool stats were retrieved (this confirms GetPoolStats was called)
	// The actual metrics recording would be tested in integration tests
}

func TestServer_Version_EdgeCases(t *testing.T) {
	logger := hclog.NewNullLogger()
	flagsConfig := config.FlagsConfig{}
	hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
	server := NewServer(logger, flagsConfig, hmacGen)

	tests := []struct {
		name        string
		request     *pb.VersionRequest
		expectError bool
	}{
		{
			name:        "nil request",
			request:     nil,
			expectError: false,
		},
		{
			name:        "empty version in request",
			request:     &pb.VersionRequest{Version: ""},
			expectError: false,
		},
		{
			name:        "very long version string",
			request:     &pb.VersionRequest{Version: strings.Repeat("v", 1000)},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := server.Version(ctx, tt.request)

			if (err != nil) != tt.expectError {
				t.Errorf("Version() error = %v, expectError %v", err, tt.expectError)
			}

			if !tt.expectError && resp != nil {
				if resp.Version != "v1alpha1" {
					t.Errorf("Expected API version v1alpha1, got %s", resp.Version)
				}
				if resp.RuntimeName != "spire-csi-provider" {
					t.Errorf("Expected runtime name spire-csi-provider, got %s", resp.RuntimeName)
				}
			}
		})
	}
}

// Helper functions
func generateTestCertAndKey() ([]byte, *rsa.PrivateKey) {
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
	return certDER, key
}

func generateTestCA() *x509.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
