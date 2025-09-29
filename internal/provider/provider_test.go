package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/go-hclog"
	"spire-csi-provider/internal/client"
	"spire-csi-provider/internal/config"
	"spire-csi-provider/internal/hmac"
	"spire-csi-provider/internal/metrics"
)

func TestNewProviderWithContext(t *testing.T) {
	tests := []struct {
		name       string
		logger     hclog.Logger
		hmacGen    *hmac.HMACGenerator
		podContext metrics.PodContext
		wantNil    bool
	}{
		{
			name:    "valid inputs",
			logger:  hclog.NewNullLogger(),
			hmacGen: hmac.NewHMACGenerator([]byte("test-key")),
			podContext: metrics.PodContext{
				Namespace:      "default",
				ServiceAccount: "test-sa",
				PodUID:         "123",
				PodName:        "test-pod",
			},
			wantNil: false,
		},
		{
			name:    "nil logger",
			logger:  nil,
			hmacGen: hmac.NewHMACGenerator([]byte("test-key")),
			podContext: metrics.PodContext{
				Namespace: "default",
			},
			wantNil: false,
		},
		{
			name:       "nil hmac generator",
			logger:     hclog.NewNullLogger(),
			hmacGen:    nil,
			podContext: metrics.PodContext{},
			wantNil:    false,
		},
		{
			name:       "empty pod context",
			logger:     hclog.NewNullLogger(),
			hmacGen:    hmac.NewHMACGenerator([]byte("test")),
			podContext: metrics.PodContext{},
			wantNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewProviderWithContext(tt.logger, tt.hmacGen, tt.podContext)
			if (provider == nil) != tt.wantNil {
				t.Errorf("NewProviderWithContext() returned nil = %v, want %v", provider == nil, tt.wantNil)
			}
			if provider != nil {
				if provider.logger != tt.logger && tt.logger != nil {
					t.Error("Logger not set correctly")
				}
				if provider.hmacGenerator != tt.hmacGen {
					t.Error("HMAC generator not set correctly")
				}
				if provider.podContext != tt.podContext {
					t.Error("Pod context not set correctly")
				}
			}
		})
	}
}

func TestHandleMountRequest_Success_X509(t *testing.T) {
	tests := []struct {
		name           string
		config         config.Config
		filePermission os.FileMode
		expectFiles    int
		expectVersions int
	}{
		{
			name: "single x509 object with custom permission",
			config: config.Config{
				TargetPath:     "/var/run/secrets",
				FilePermission: 0644,
				Parameters: config.Parameters{
					TrustDomain: "example.org",
					PodInfo: config.PodInfo{
						Namespace:          "default",
						ServiceAccountName: "test-sa",
						UID:                "123",
						Name:               "test-pod",
					},
					Selectors: []config.Selector{
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "sa:test-sa"},
					},
					Objects: []config.Object{
						{
							ObjectName:     "x509-svid",
							Type:           "x509-svid",
							Paths:          []string{"/cert.pem", "/key.pem", "/bundle.pem"},
							FilePermission: 0600,
						},
					},
				},
			},
			filePermission: 0600,
			expectFiles:    3,
			expectVersions: 1,
		},
		{
			name: "x509 with default permission",
			config: config.Config{
				TargetPath:     "/var/run/secrets",
				FilePermission: 0644,
				Parameters: config.Parameters{
					TrustDomain: "prod.example.org",
					PodInfo: config.PodInfo{
						Namespace:          "production",
						ServiceAccountName: "prod-sa",
						UID:                "456",
						Name:               "prod-pod",
					},
					Selectors: []config.Selector{
						{Type: "k8s", Value: "ns:production"},
						{Type: "k8s", Value: "sa:prod-sa"},
						{Type: "k8s", Value: "pod-uid:456"},
					},
					Objects: []config.Object{
						{
							ObjectName: "prod-x509",
							Type:       "x509-svid",
							Paths:      []string{"/tls/cert.pem", "/tls/key.pem", "/tls/ca.pem"},
						},
					},
				},
			},
			filePermission: 0644,
			expectFiles:    3,
			expectVersions: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
			podContext := metrics.PodContext{
				Namespace:      tt.config.Parameters.PodInfo.Namespace,
				ServiceAccount: tt.config.Parameters.PodInfo.ServiceAccountName,
				PodUID:         string(tt.config.Parameters.PodInfo.UID),
				PodName:        tt.config.Parameters.PodInfo.Name,
			}

			cert, key := generateTestCertificate(t)
			caCert := generateTestCACertificate(t)

			tlsCert := &tls.Certificate{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  key,
				Leaf:        cert,
			}

			mockClient := client.NewMockSpireClient(ctrl)
			mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil)
			mockClient.EXPECT().GetCertificateForIdentity(gomock.Any()).Return(tlsCert, nil)
			mockClient.EXPECT().GetCACertificates(gomock.Any()).Return([]*x509.Certificate{caCert}, nil)

			mockPool := client.NewMockClientPoolInterface(ctrl)
			mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
			mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()

			provider := NewProviderWithClientPool(logger, hmacGen, podContext, mockPool)

			flagsConfig := config.FlagsConfig{
				SpireSocketPath: "/run/spire/socket",
			}

			ctx := context.Background()
			resp, err := provider.HandleMountRequest(ctx, tt.config, flagsConfig)

			if err != nil {
				t.Fatalf("HandleMountRequest failed: %v", err)
			}

			if len(resp.Files) != tt.expectFiles {
				t.Errorf("Expected %d files, got %d", tt.expectFiles, len(resp.Files))
			}
			if len(resp.ObjectVersion) != tt.expectVersions {
				t.Errorf("Expected %d object versions, got %d", tt.expectVersions, len(resp.ObjectVersion))
			}

			for i, file := range resp.Files {
				expectedMode := int32(tt.filePermission)
				if file.Mode != expectedMode {
					t.Errorf("File %d: expected mode %o, got %o", i, expectedMode, file.Mode)
				}
			}
		})
	}
}

func TestHandleMountRequest_Success_JWT(t *testing.T) {
	tests := []struct {
		name      string
		audiences []string
		jwtToken  string
		paths     []string
	}{
		{
			name:      "single audience",
			audiences: []string{"audience1"},
			jwtToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			paths:     []string{"/token.jwt"},
		},
		{
			name:      "multiple audiences",
			audiences: []string{"audience1", "audience2", "audience3"},
			jwtToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkMSIsImF1ZDIiXX0.2sSJKWgOcvXj0pJ_Uw6RkF8w0e_PINkucBLsVeGQoKY",
			paths:     []string{"/var/run/secrets/token"},
		},
		{
			name:      "special characters in audience",
			audiences: []string{"https://api.example.com", "urn:audience:test"},
			jwtToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJzcGVjaWFsIn0.hc6l8bLMqS7Kic7OFoVvTvNTLV7TEuySJyzpq-1WdBE",
			paths:     []string{"/jwt/token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
			podContext := metrics.PodContext{
				Namespace:      "default",
				ServiceAccount: "test-sa",
				PodUID:         "123",
				PodName:        "test-pod",
			}

			mockClient := client.NewMockSpireClient(ctrl)
			mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil)
			mockClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), tt.audiences).Return(tt.jwtToken, nil)

			mockPool := client.NewMockClientPoolInterface(ctrl)
			mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
			mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()

			provider := NewProviderWithClientPool(logger, hmacGen, podContext, mockPool)

			cfg := config.Config{
				TargetPath:     "/var/run/secrets",
				FilePermission: 0644,
				Parameters: config.Parameters{
					TrustDomain: "example.org",
					PodInfo: config.PodInfo{
						Namespace:          "default",
						ServiceAccountName: "test-sa",
						UID:                "123",
						Name:               "test-pod",
					},
					Selectors: []config.Selector{
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "sa:test-sa"},
					},
					Objects: []config.Object{
						{
							ObjectName: "jwt-svid",
							Type:       "jwt-svid",
							Audience:   tt.audiences,
							Paths:      tt.paths,
						},
					},
				},
			}

			flagsConfig := config.FlagsConfig{
				SpireSocketPath: "/run/spire/socket",
			}

			ctx := context.Background()
			resp, err := provider.HandleMountRequest(ctx, cfg, flagsConfig)

			if err != nil {
				t.Fatalf("HandleMountRequest failed: %v", err)
			}

			if len(resp.Files) != 1 {
				t.Errorf("Expected 1 file, got %d", len(resp.Files))
			}
			if resp.Files[0].Path != tt.paths[0] {
				t.Errorf("Expected path %s, got %s", tt.paths[0], resp.Files[0].Path)
			}
			if string(resp.Files[0].Contents) != tt.jwtToken {
				t.Error("JWT token content mismatch")
			}
		})
	}
}

func TestHandleMountRequest_MultipleObjects(t *testing.T) {
	tests := []struct {
		name           string
		objects        []config.Object
		expectedFiles  int
		expectedObjVer int
	}{
		{
			name: "x509 and jwt",
			objects: []config.Object{
				{
					ObjectName: "x509-svid",
					Type:       "x509-svid",
					Paths:      []string{"/cert.pem", "/key.pem", "/bundle.pem"},
				},
				{
					ObjectName: "jwt-svid",
					Type:       "jwt-svid",
					Audience:   []string{"audience1"},
					Paths:      []string{"/token.jwt"},
				},
			},
			expectedFiles:  4,
			expectedObjVer: 2,
		},
		{
			name: "multiple x509 objects",
			objects: []config.Object{
				{
					ObjectName: "x509-1",
					Type:       "x509-svid",
					Paths:      []string{"/tls1/cert.pem", "/tls1/key.pem", "/tls1/bundle.pem"},
				},
				{
					ObjectName: "x509-2",
					Type:       "x509-svid",
					Paths:      []string{"/tls2/cert.pem", "/tls2/key.pem", "/tls2/bundle.pem"},
				},
			},
			expectedFiles:  6,
			expectedObjVer: 2,
		},
		{
			name: "multiple jwt objects",
			objects: []config.Object{
				{
					ObjectName: "jwt-1",
					Type:       "jwt-svid",
					Audience:   []string{"aud1"},
					Paths:      []string{"/token1.jwt"},
				},
				{
					ObjectName: "jwt-2",
					Type:       "jwt-svid",
					Audience:   []string{"aud2", "aud3"},
					Paths:      []string{"/token2.jwt"},
				},
			},
			expectedFiles:  2,
			expectedObjVer: 2,
		},
		{
			name: "three mixed objects",
			objects: []config.Object{
				{
					ObjectName:     "x509-main",
					Type:           "x509-svid",
					Paths:          []string{"/main/cert.pem", "/main/key.pem", "/main/bundle.pem"},
					FilePermission: 0600,
				},
				{
					ObjectName: "jwt-api",
					Type:       "jwt-svid",
					Audience:   []string{"api.example.com"},
					Paths:      []string{"/api/token.jwt"},
				},
				{
					ObjectName:     "x509-backup",
					Type:           "x509-svid",
					Paths:          []string{"/backup/cert.pem", "/backup/key.pem", "/backup/bundle.pem"},
					FilePermission: 0400,
				},
			},
			expectedFiles:  7,
			expectedObjVer: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
			podContext := metrics.PodContext{
				Namespace:      "default",
				ServiceAccount: "test-sa",
				PodUID:         "123",
				PodName:        "test-pod",
			}

			cert, key := generateTestCertificate(t)
			caCert := generateTestCACertificate(t)

			tlsCert := &tls.Certificate{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  key,
				Leaf:        cert,
			}

			mockClient := client.NewMockSpireClient(ctrl)
			mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil)

			for _, obj := range tt.objects {
				if obj.Type == "x509-svid" {
					mockClient.EXPECT().GetCertificateForIdentity(gomock.Any()).Return(tlsCert, nil)
					mockClient.EXPECT().GetCACertificates(gomock.Any()).Return([]*x509.Certificate{caCert}, nil)
				} else if obj.Type == "jwt-svid" {
					mockClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), obj.Audience).Return("test-jwt-token", nil)
				}
			}

			mockPool := client.NewMockClientPoolInterface(ctrl)
			mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
			mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()

			provider := NewProviderWithClientPool(logger, hmacGen, podContext, mockPool)

			cfg := config.Config{
				TargetPath:     "/var/run/secrets",
				FilePermission: 0644,
				Parameters: config.Parameters{
					TrustDomain: "example.org",
					PodInfo: config.PodInfo{
						Namespace:          "default",
						ServiceAccountName: "test-sa",
						UID:                "123",
						Name:               "test-pod",
					},
					Selectors: []config.Selector{
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "sa:test-sa"},
					},
					Objects: tt.objects,
				},
			}

			flagsConfig := config.FlagsConfig{
				SpireSocketPath: "/run/spire/socket",
			}

			ctx := context.Background()
			resp, err := provider.HandleMountRequest(ctx, cfg, flagsConfig)

			if err != nil {
				t.Fatalf("HandleMountRequest failed: %v", err)
			}

			if len(resp.Files) != tt.expectedFiles {
				t.Errorf("Expected %d files, got %d", tt.expectedFiles, len(resp.Files))
			}
			if len(resp.ObjectVersion) != tt.expectedObjVer {
				t.Errorf("Expected %d object versions, got %d", tt.expectedObjVer, len(resp.ObjectVersion))
			}
		})
	}
}

func TestHandleMountRequest_Errors(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*gomock.Controller) (client.SpireClient, client.ClientPoolInterface)
		config      config.Config
		flagsConfig config.FlagsConfig
		wantErr     string
	}{
		{
			name: "empty socket path",
			setupMock: func(ctrl *gomock.Controller) (client.SpireClient, client.ClientPoolInterface) {
				mockClient := client.NewMockSpireClient(ctrl)
				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil).AnyTimes()
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return().AnyTimes()
				return mockClient, mockPool
			},
			config: config.Config{
				TargetPath: "/var/run/secrets",
				Parameters: config.Parameters{
					TrustDomain: "example.org",
					// Add valid selectors to avoid early SPIFFE ID failure
					Selectors: []config.Selector{
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "sa:test-sa"},
					},
					Objects: []config.Object{
						{ObjectName: "test", Type: "x509-svid", Paths: []string{"/a", "/b", "/c"}},
					},
				},
			},
			flagsConfig: config.FlagsConfig{SpireSocketPath: ""},
			wantErr:     "SPIRE socket path not specified",
		},
		{
			name: "client pool acquire error",
			setupMock: func(ctrl *gomock.Controller) (client.SpireClient, client.ClientPoolInterface) {
				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("pool error"))
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return().AnyTimes()
				return nil, mockPool
			},
			config: config.Config{
				TargetPath: "/var/run/secrets",
				Parameters: config.Parameters{
					TrustDomain: "example.org",
					// Add valid selectors
					Selectors: []config.Selector{
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "sa:test-sa"},
					},
					Objects: []config.Object{
						{ObjectName: "test", Type: "x509-svid", Paths: []string{"/a", "/b", "/c"}},
					},
				},
			},
			flagsConfig: config.FlagsConfig{SpireSocketPath: "/socket"},
			wantErr:     "failed to acquire SPIRE client from pool",
		},
		{
			name: "wait for SVID timeout",
			setupMock: func(ctrl *gomock.Controller) (client.SpireClient, client.ClientPoolInterface) {
				mockClient := client.NewMockSpireClient(ctrl)
				mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("timeout waiting for SVID"))

				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()
				return mockClient, mockPool
			},
			config: config.Config{
				TargetPath: "/var/run/secrets",
				Parameters: config.Parameters{
					TrustDomain: "example.org",
					Selectors: []config.Selector{
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "sa:test"},
					},
					Objects: []config.Object{
						{ObjectName: "test", Type: "x509-svid", Paths: []string{"/a", "/b", "/c"}},
					},
				},
			},
			flagsConfig: config.FlagsConfig{SpireSocketPath: "/socket"},
			wantErr:     "failed waiting for SVID",
		},
		{
			name: "wait for trust bundle timeout",
			setupMock: func(ctrl *gomock.Controller) (client.SpireClient, client.ClientPoolInterface) {
				mockClient := client.NewMockSpireClient(ctrl)
				mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(errors.New("timeout waiting for trust bundle"))

				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()
				return mockClient, mockPool
			},
			config: config.Config{
				TargetPath: "/var/run/secrets",
				Parameters: config.Parameters{
					TrustDomain: "example.org",
					Selectors: []config.Selector{
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "sa:test"},
					},
					Objects: []config.Object{
						{ObjectName: "test", Type: "x509-svid", Paths: []string{"/a", "/b", "/c"}},
					},
				},
			},
			flagsConfig: config.FlagsConfig{SpireSocketPath: "/socket"},
			wantErr:     "failed waiting for trust bundle",
		},
		{
			name: "unsupported object type",
			setupMock: func(ctrl *gomock.Controller) (client.SpireClient, client.ClientPoolInterface) {
				mockClient := client.NewMockSpireClient(ctrl)
				mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil)

				mockPool := client.NewMockClientPoolInterface(ctrl)
				mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
				mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()
				return mockClient, mockPool
			},
			config: config.Config{
				TargetPath: "/var/run/secrets",
				Parameters: config.Parameters{
					TrustDomain: "example.org",
					Selectors: []config.Selector{
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "sa:test"},
					},
					Objects: []config.Object{
						{ObjectName: "bad", Type: "unsupported", Paths: []string{"/test"}},
					},
				},
			},
			flagsConfig: config.FlagsConfig{SpireSocketPath: "/socket"},
			wantErr:     "unsupported object type",
		},
		{
			name: "empty SPIFFE ID - missing selectors",
			setupMock: func(ctrl *gomock.Controller) (client.SpireClient, client.ClientPoolInterface) {
				// This test should fail before acquiring client
				mockPool := client.NewMockClientPoolInterface(ctrl)
				// Don't expect any calls since we should fail early
				return nil, mockPool
			},
			config: config.Config{
				TargetPath: "/var/run/secrets",
				Parameters: config.Parameters{
					TrustDomain: "example.org",
					// No selectors - will fail at SPIFFE ID building
					Objects: []config.Object{
						{ObjectName: "test", Type: "x509-svid", Paths: []string{"/a", "/b", "/c"}},
					},
				},
			},
			flagsConfig: config.FlagsConfig{SpireSocketPath: "/socket"},
			wantErr:     "unable to build valid SPIFFE ID from selectors",
		},
		{
			name: "empty SPIFFE ID - missing namespace selector",
			setupMock: func(ctrl *gomock.Controller) (client.SpireClient, client.ClientPoolInterface) {
				// This test should fail before acquiring client
				mockPool := client.NewMockClientPoolInterface(ctrl)
				// Don't expect any calls since we should fail early
				return nil, mockPool
			},
			config: config.Config{
				TargetPath: "/var/run/secrets",
				Parameters: config.Parameters{
					TrustDomain: "example.org",
					Selectors: []config.Selector{
						// Missing namespace selector
						{Type: "k8s", Value: "sa:test-sa"},
						{Type: "k8s", Value: "pod-uid:123"},
					},
					Objects: []config.Object{
						{ObjectName: "test", Type: "x509-svid", Paths: []string{"/a", "/b", "/c"}},
					},
				},
			},
			flagsConfig: config.FlagsConfig{SpireSocketPath: "/socket"},
			wantErr:     "unable to build valid SPIFFE ID from selectors",
		},
		{
			name: "empty SPIFFE ID - missing service account selector",
			setupMock: func(ctrl *gomock.Controller) (client.SpireClient, client.ClientPoolInterface) {
				// This test should fail before acquiring client
				mockPool := client.NewMockClientPoolInterface(ctrl)
				// Don't expect any calls since we should fail early
				return nil, mockPool
			},
			config: config.Config{
				TargetPath: "/var/run/secrets",
				Parameters: config.Parameters{
					TrustDomain: "example.org",
					Selectors: []config.Selector{
						// Missing service account selector
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "pod-uid:123"},
					},
					Objects: []config.Object{
						{ObjectName: "test", Type: "x509-svid", Paths: []string{"/a", "/b", "/c"}},
					},
				},
			},
			flagsConfig: config.FlagsConfig{SpireSocketPath: "/socket"},
			wantErr:     "unable to build valid SPIFFE ID from selectors",
		},
		{
			name: "empty SPIFFE ID - missing trust domain",
			setupMock: func(ctrl *gomock.Controller) (client.SpireClient, client.ClientPoolInterface) {
				// This test should fail before acquiring client
				mockPool := client.NewMockClientPoolInterface(ctrl)
				// Don't expect any calls since we should fail early
				return nil, mockPool
			},
			config: config.Config{
				TargetPath: "/var/run/secrets",
				Parameters: config.Parameters{
					// Missing TrustDomain
					Selectors: []config.Selector{
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "sa:test-sa"},
					},
					Objects: []config.Object{
						{ObjectName: "test", Type: "x509-svid", Paths: []string{"/a", "/b", "/c"}},
					},
				},
			},
			flagsConfig: config.FlagsConfig{SpireSocketPath: "/socket"},
			wantErr:     "unable to build valid SPIFFE ID from selectors",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
			podContext := metrics.PodContext{}

			_, mockPool := tt.setupMock(ctrl)

			provider := NewProviderWithClientPool(logger, hmacGen, podContext, mockPool)

			ctx := context.Background()
			_, err := provider.HandleMountRequest(ctx, tt.config, tt.flagsConfig)

			if err == nil {
				t.Fatal("Expected error but got none")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestHandleMountRequest_WithoutPool(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := hclog.NewNullLogger()
	hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
	podContext := metrics.PodContext{
		Namespace:      "default",
		ServiceAccount: "test-sa",
		PodUID:         "123",
		PodName:        "test-pod",
	}

	provider := NewProviderWithContext(logger, hmacGen, podContext)

	cfg := config.Config{
		TargetPath:     "/var/run/secrets",
		FilePermission: 0644,
		Parameters: config.Parameters{
			TrustDomain: "example.org",
			PodInfo: config.PodInfo{
				Namespace:          "default",
				ServiceAccountName: "test-sa",
				UID:                "123",
				Name:               "test-pod",
			},
			Selectors: []config.Selector{
				{Type: "k8s", Value: "ns:default"},
				{Type: "k8s", Value: "sa:test-sa"},
			},
			Objects: []config.Object{
				{
					ObjectName: "jwt-svid",
					Type:       "jwt-svid",
					Audience:   []string{"audience1"},
					Paths:      []string{"/token.jwt"},
				},
			},
		},
	}

	flagsConfig := config.FlagsConfig{
		SpireSocketPath: "/run/spire/socket",
	}

	mockClient := client.NewMockSpireClient(ctrl)
	mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil)
	mockClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return("test-jwt", nil)

	// Manually set the client (simulating an already initialized client)
	provider.spireClient = mockClient
	provider.clientConfig = client.Config{
		SpireSocketPath:   flagsConfig.SpireSocketPath,
		SpiffeTrustDomain: cfg.Parameters.TrustDomain,
	}

	ctx := context.Background()
	resp, err := provider.HandleMountRequest(ctx, cfg, flagsConfig)

	if err != nil {
		t.Fatalf("HandleMountRequest failed: %v", err)
	}

	if len(resp.Files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(resp.Files))
	}
	if resp.Files[0].Path != "/token.jwt" {
		t.Errorf("Expected path /token.jwt, got %s", resp.Files[0].Path)
	}
}

func TestBuildSpiffeIDFromSelectors(t *testing.T) {
	logger := hclog.NewNullLogger()
	hmacGen := hmac.NewHMACGenerator([]byte("test"))
	podContext := metrics.PodContext{}
	provider := NewProviderWithContext(logger, hmacGen, podContext)

	tests := []struct {
		name   string
		params config.Parameters
		want   string
	}{
		{
			name: "complete SPIFFE ID",
			params: config.Parameters{
				TrustDomain: "example.org",
				Selectors: []config.Selector{
					{Type: "k8s", Value: "ns:production"},
					{Type: "k8s", Value: "sa:frontend"},
					{Type: "k8s", Value: "pod-uid:123"},
				},
			},
			want: "spiffe://example.org/ns/production/sa/frontend",
		},
		{
			name: "selectors in different order",
			params: config.Parameters{
				TrustDomain: "example.org",
				Selectors: []config.Selector{
					{Type: "k8s", Value: "pod-uid:123"},
					{Type: "k8s", Value: "sa:backend"},
					{Type: "k8s", Value: "ns:staging"},
				},
			},
			want: "spiffe://example.org/ns/staging/sa/backend",
		},
		{
			name: "with extra selectors",
			params: config.Parameters{
				TrustDomain: "example.org",
				Selectors: []config.Selector{
					{Type: "k8s", Value: "ns:default"},
					{Type: "k8s", Value: "sa:admin"},
					{Type: "k8s", Value: "pod-uid:abc"},
					{Type: "k8s", Value: "pod-name:test-pod"},
					{Type: "custom", Value: "extra:value"},
				},
			},
			want: "spiffe://example.org/ns/default/sa/admin",
		},
		{
			name: "missing namespace",
			params: config.Parameters{
				TrustDomain: "example.org",
				Selectors: []config.Selector{
					{Type: "k8s", Value: "sa:frontend"},
					{Type: "k8s", Value: "pod-uid:123"},
				},
			},
			want: "",
		},
		{
			name: "missing service account",
			params: config.Parameters{
				TrustDomain: "example.org",
				Selectors: []config.Selector{
					{Type: "k8s", Value: "ns:production"},
					{Type: "k8s", Value: "pod-uid:123"},
				},
			},
			want: "",
		},
		{
			name: "missing trust domain",
			params: config.Parameters{
				Selectors: []config.Selector{
					{Type: "k8s", Value: "ns:production"},
					{Type: "k8s", Value: "sa:frontend"},
				},
			},
			want: "",
		},
		{
			name: "empty selectors",
			params: config.Parameters{
				TrustDomain: "example.org",
				Selectors:   []config.Selector{},
			},
			want: "",
		},
		{
			name: "nil selectors",
			params: config.Parameters{
				TrustDomain: "example.org",
				Selectors:   nil,
			},
			want: "",
		},
		{
			name: "non-k8s selectors only",
			params: config.Parameters{
				TrustDomain: "example.org",
				Selectors: []config.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
					{Type: "docker", Value: "label:app=test"},
				},
			},
			want: "",
		},
		{
			name: "mixed selector types",
			params: config.Parameters{
				TrustDomain: "example.org",
				Selectors: []config.Selector{
					{Type: "k8s", Value: "ns:hybrid"},
					{Type: "unix", Value: "uid:1000"},
					{Type: "k8s", Value: "sa:hybrid-sa"},
					{Type: "docker", Value: "image:test"},
				},
			},
			want: "spiffe://example.org/ns/hybrid/sa/hybrid-sa",
		},
		{
			name: "special characters in values",
			params: config.Parameters{
				TrustDomain: "test.example.org",
				Selectors: []config.Selector{
					{Type: "k8s", Value: "ns:kube-system"},
					{Type: "k8s", Value: "sa:dns-controller"},
				},
			},
			want: "spiffe://test.example.org/ns/kube-system/sa/dns-controller",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := provider.buildSpiffeIDFromSelectors(tt.params)
			if got != tt.want {
				t.Errorf("buildSpiffeIDFromSelectors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFetchX509SVID_Success(t *testing.T) {
	tests := []struct {
		name        string
		certChain   int
		caCerts     int
		keyType     interface{}
		expectError bool
	}{
		{
			name:      "single cert with RSA key",
			certChain: 1,
			caCerts:   1,
			keyType:   &rsa.PrivateKey{},
		},
		{
			name:      "cert chain with intermediate",
			certChain: 2,
			caCerts:   2,
			keyType:   &rsa.PrivateKey{},
		},
		{
			name:      "multiple CA certs",
			certChain: 1,
			caCerts:   3,
			keyType:   &rsa.PrivateKey{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			hmacGen := hmac.NewHMACGenerator([]byte("test"))
			podContext := metrics.PodContext{}
			provider := NewProviderWithContext(logger, hmacGen, podContext)

			var certChain [][]byte
			for i := 0; i < tt.certChain; i++ {
				cert, _ := generateTestCertificate(t)
				certChain = append(certChain, cert.Raw)
			}

			var caCerts []*x509.Certificate
			for i := 0; i < tt.caCerts; i++ {
				caCerts = append(caCerts, generateTestCACertificate(t))
			}

			key, _ := rsa.GenerateKey(rand.Reader, 2048)
			tlsCert := &tls.Certificate{
				Certificate: certChain,
				PrivateKey:  key,
			}

			mockClient := client.NewMockSpireClient(ctrl)
			mockClient.EXPECT().GetCertificateForIdentity(gomock.Any()).Return(tlsCert, nil)
			mockClient.EXPECT().GetCACertificates(gomock.Any()).Return(caCerts, nil)

			object := config.Object{
				ObjectName: "test",
				Type:       "x509-svid",
				Paths:      []string{"/cert", "/key", "/bundle"},
			}

			ctx := context.Background()
			result, err := provider.fetchX509SVID(ctx, mockClient, object, "spiffe://example.org/test")

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}

				if len(result) != 3 {
					t.Errorf("Expected 3 paths in result, got %d", len(result))
				}

				if !strings.Contains(string(result["/cert"]), "BEGIN CERTIFICATE") {
					t.Error("Certificate PEM not found")
				}

				if !strings.Contains(string(result["/key"]), "BEGIN PRIVATE KEY") {
					t.Error("Private key PEM not found")
				}

				bundleCertCount := strings.Count(string(result["/bundle"]), "BEGIN CERTIFICATE")
				if bundleCertCount != tt.caCerts {
					t.Errorf("Expected %d CA certs in bundle, found %d", tt.caCerts, bundleCertCount)
				}
			}
		})
	}
}

func TestFetchJWTSVID_Success(t *testing.T) {
	tests := []struct {
		name      string
		audiences []string
		token     string
		paths     []string
	}{
		{
			name:      "standard JWT",
			audiences: []string{"test-audience"},
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			paths:     []string{"/token.jwt"},
		},
		{
			name:      "empty JWT",
			audiences: []string{"empty"},
			token:     "",
			paths:     []string{"/empty.jwt"},
		},
		{
			name:      "very long JWT",
			audiences: []string{"long"},
			token:     strings.Repeat("a", 10000),
			paths:     []string{"/long.jwt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			hmacGen := hmac.NewHMACGenerator([]byte("test"))
			podContext := metrics.PodContext{}
			provider := NewProviderWithContext(logger, hmacGen, podContext)

			mockClient := client.NewMockSpireClient(ctrl)
			mockClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), tt.audiences).Return(tt.token, nil)

			object := config.Object{
				ObjectName: "test",
				Type:       "jwt-svid",
				Audience:   tt.audiences,
				Paths:      tt.paths,
			}

			ctx := context.Background()
			result, err := provider.fetchJWTSVID(ctx, mockClient, object, "spiffe://example.org/test")

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(result) != 1 {
				t.Errorf("Expected 1 path in result, got %d", len(result))
			}

			if string(result[tt.paths[0]]) != tt.token {
				t.Errorf("Token mismatch: got %s, want %s", result[tt.paths[0]], tt.token)
			}
		})
	}
}

func TestProvider_ConcurrentRequests(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := hclog.NewNullLogger()
	hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
	podContext := metrics.PodContext{
		Namespace:      "default",
		ServiceAccount: "test-sa",
		PodUID:         "123",
		PodName:        "test-pod",
	}

	// Create mock client that can handle concurrent calls
	mockClient := client.NewMockSpireClient(ctrl)
	mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockClient.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return("test-jwt", nil).AnyTimes()

	// Create mock pool
	mockPool := client.NewMockClientPoolInterface(ctrl)
	mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil).AnyTimes()
	mockPool.EXPECT().ReleaseClient(gomock.Any()).Return().AnyTimes()

	provider := NewProviderWithClientPool(logger, hmacGen, podContext, mockPool)

	cfg := config.Config{
		TargetPath:     "/var/run/secrets",
		FilePermission: 0644,
		Parameters: config.Parameters{
			TrustDomain: "example.org",
			PodInfo: config.PodInfo{
				Namespace:          "default",
				ServiceAccountName: "test-sa",
				UID:                "123",
				Name:               "test-pod",
			},
			Selectors: []config.Selector{
				{Type: "k8s", Value: "ns:default"},
				{Type: "k8s", Value: "sa:test-sa"},
			},
			Objects: []config.Object{
				{
					ObjectName: "jwt-svid",
					Type:       "jwt-svid",
					Audience:   []string{"audience1"},
					Paths:      []string{"/token.jwt"},
				},
			},
		},
	}

	flagsConfig := config.FlagsConfig{
		SpireSocketPath: "/run/spire/socket",
	}

	// Run multiple concurrent requests
	numRequests := 10
	var wg sync.WaitGroup
	errors := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			_, err := provider.HandleMountRequest(ctx, cfg, flagsConfig)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent request failed: %v", err)
	}
}

func TestProvider_Stop(t *testing.T) {
	tests := []struct {
		name        string
		hasClient   bool
		stopError   error
		expectError bool
	}{
		{
			name:        "with client",
			hasClient:   true,
			stopError:   nil,
			expectError: false,
		},
		{
			name:        "without client",
			hasClient:   false,
			stopError:   nil,
			expectError: false,
		},
		{
			name:        "with client stop error",
			hasClient:   true,
			stopError:   errors.New("stop failed"),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			hmacGen := hmac.NewHMACGenerator([]byte("test"))
			podContext := metrics.PodContext{}
			provider := NewProviderWithContext(logger, hmacGen, podContext)

			if tt.hasClient {
				mockClient := client.NewMockSpireClient(ctrl)
				mockClient.EXPECT().Stop().Return(tt.stopError)
				provider.spireClient = mockClient
			}

			err := provider.Stop()
			if (err != nil) != tt.expectError {
				t.Errorf("Stop() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestConvertConfigSelectorsToAPISelectors(t *testing.T) {
	tests := []struct {
		name            string
		configSelectors []config.Selector
		expected        int
	}{
		{
			name: "standard selectors",
			configSelectors: []config.Selector{
				{Type: "k8s", Value: "ns:default"},
				{Type: "k8s", Value: "sa:test"},
				{Type: "unix", Value: "uid:1000"},
			},
			expected: 3,
		},
		{
			name:            "empty selectors",
			configSelectors: []config.Selector{},
			expected:        0,
		},
		{
			name:            "nil selectors",
			configSelectors: nil,
			expected:        0,
		},
		{
			name: "single selector",
			configSelectors: []config.Selector{
				{Type: "test", Value: "value"},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiSelectors := convertConfigSelectorsToAPISelectors(tt.configSelectors)

			if len(apiSelectors) != tt.expected {
				t.Errorf("Expected %d selectors, got %d", tt.expected, len(apiSelectors))
			}

			for i, sel := range apiSelectors {
				if i < len(tt.configSelectors) {
					if sel.Type != tt.configSelectors[i].Type {
						t.Errorf("Selector %d: Type = %v, want %v", i, sel.Type, tt.configSelectors[i].Type)
					}
					if sel.Value != tt.configSelectors[i].Value {
						t.Errorf("Selector %d: Value = %v, want %v", i, sel.Value, tt.configSelectors[i].Value)
					}
				}
			}
		})
	}
}

func TestFetchX509SVID_FederatedBundles(t *testing.T) {
	tests := []struct {
		name                 string
		includeFederated     bool
		mergeFederatedBundle bool
		bundlesByDomain      map[string][]*x509.Certificate
		getBundlesError      error
		expectFiles          map[string]bool
		fallbackToRegular    bool
		verifyCertCount      map[string]int
	}{
		{
			name:             "federated disabled",
			includeFederated: false,
			expectFiles: map[string]bool{
				"/cert.pem":   true,
				"/key.pem":    true,
				"/bundle.pem": true,
			},
			verifyCertCount: map[string]int{
				"/bundle.pem": 1,
			},
		},
		{
			name:                 "federated enabled - merged bundles",
			includeFederated:     true,
			mergeFederatedBundle: true,
			bundlesByDomain: map[string][]*x509.Certificate{
				"example.org":    {generateTestCACertificate(t)},
				"federated1.com": {generateTestCACertificate(t)},
				"federated2.com": {generateTestCACertificate(t), generateTestCACertificate(t)},
			},
			expectFiles: map[string]bool{
				"/cert.pem":   true,
				"/key.pem":    true,
				"/bundle.pem": true,
			},
			verifyCertCount: map[string]int{
				"/bundle.pem": 4,
			},
		},
		{
			name:                 "federated enabled - separate bundles",
			includeFederated:     true,
			mergeFederatedBundle: false,
			bundlesByDomain: map[string][]*x509.Certificate{
				"example.org":    {generateTestCACertificate(t)},
				"federated1.com": {generateTestCACertificate(t)},
				"federated2.com": {generateTestCACertificate(t)},
			},
			expectFiles: map[string]bool{
				"/cert.pem":                  true,
				"/key.pem":                   true,
				"/bundle.pem":                true,
				"/federated1_com-bundle.pem": true,
				"/federated2_com-bundle.pem": true,
			},
			verifyCertCount: map[string]int{
				"/bundle.pem":                1,
				"/federated1_com-bundle.pem": 1,
				"/federated2_com-bundle.pem": 1,
			},
		},
		{
			name:                 "federated enabled - main domain with spiffe prefix",
			includeFederated:     true,
			mergeFederatedBundle: false,
			bundlesByDomain: map[string][]*x509.Certificate{
				"spiffe://example.org": {generateTestCACertificate(t)},
				"partner.com":          {generateTestCACertificate(t)},
			},
			expectFiles: map[string]bool{
				"/cert.pem":               true,
				"/key.pem":                true,
				"/bundle.pem":             true,
				"/partner_com-bundle.pem": true,
			},
			verifyCertCount: map[string]int{
				"/bundle.pem":             1,
				"/partner_com-bundle.pem": 1,
			},
		},
		{
			name:                 "federated enabled - empty main domain key",
			includeFederated:     true,
			mergeFederatedBundle: false,
			bundlesByDomain: map[string][]*x509.Certificate{
				"":              {generateTestCACertificate(t)},
				"federated.com": {generateTestCACertificate(t)},
			},
			expectFiles: map[string]bool{
				"/cert.pem":                 true,
				"/key.pem":                  true,
				"/bundle.pem":               true,
				"/federated_com-bundle.pem": true,
			},
			verifyCertCount: map[string]int{
				"/bundle.pem":               1,
				"/federated_com-bundle.pem": 1,
			},
		},
		{
			name:                 "federated enabled - no main domain in map",
			includeFederated:     true,
			mergeFederatedBundle: false,
			bundlesByDomain: map[string][]*x509.Certificate{
				"other1.com": {generateTestCACertificate(t)},
				"other2.com": {generateTestCACertificate(t)},
			},
			expectFiles: map[string]bool{
				"/cert.pem":              true,
				"/key.pem":               true,
				"/bundle.pem":            true,
				"/other1_com-bundle.pem": true,
				"/other2_com-bundle.pem": true,
			},
			fallbackToRegular: true,
			verifyCertCount: map[string]int{
				"/bundle.pem":            1,
				"/other1_com-bundle.pem": 1,
				"/other2_com-bundle.pem": 1,
			},
		},
		{
			name:             "federated enabled - GetBundlesByDomain error",
			includeFederated: true,
			getBundlesError:  errors.New("failed to get bundles"),
			expectFiles: map[string]bool{
				"/cert.pem":   true,
				"/key.pem":    true,
				"/bundle.pem": true,
			},
			fallbackToRegular: true,
			verifyCertCount: map[string]int{
				"/bundle.pem": 1,
			},
		},
		{
			name:                 "federated enabled - domain with no certificates",
			includeFederated:     true,
			mergeFederatedBundle: false,
			bundlesByDomain: map[string][]*x509.Certificate{
				"example.org": {generateTestCACertificate(t)},
				"empty.com":   {},
			},
			expectFiles: map[string]bool{
				"/cert.pem":   true,
				"/key.pem":    true,
				"/bundle.pem": true,
			},
			verifyCertCount: map[string]int{
				"/bundle.pem": 1,
			},
		},
		{
			name:                 "federated enabled - complex domain normalization",
			includeFederated:     true,
			mergeFederatedBundle: false,
			bundlesByDomain: map[string][]*x509.Certificate{
				"example.org":              {generateTestCACertificate(t)},
				"spiffe://test.domain.com": {generateTestCACertificate(t)},
				"sub.domain:8080":          {generateTestCACertificate(t)},
			},
			expectFiles: map[string]bool{
				"/cert.pem":                   true,
				"/key.pem":                    true,
				"/bundle.pem":                 true,
				"/test_domain_com-bundle.pem": true,
				"/sub_domain_8080-bundle.pem": true,
			},
			verifyCertCount: map[string]int{
				"/bundle.pem":                 1,
				"/test_domain_com-bundle.pem": 1,
				"/sub_domain_8080-bundle.pem": 1,
			},
		},
		{
			name:                 "federated enabled - merged with multiple certs per domain",
			includeFederated:     true,
			mergeFederatedBundle: true,
			bundlesByDomain: map[string][]*x509.Certificate{
				"example.org": {
					generateTestCACertificate(t),
					generateTestCACertificate(t),
				},
				"partner.com": {
					generateTestCACertificate(t),
					generateTestCACertificate(t),
					generateTestCACertificate(t),
				},
			},
			expectFiles: map[string]bool{
				"/cert.pem":   true,
				"/key.pem":    true,
				"/bundle.pem": true,
			},
			verifyCertCount: map[string]int{
				"/bundle.pem": 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()
			hmacGen := hmac.NewHMACGenerator([]byte("test"))
			podContext := metrics.PodContext{}
			provider := NewProviderWithContext(logger, hmacGen, podContext)

			cert, key := generateTestCertificate(t)
			tlsCert := &tls.Certificate{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  key,
			}

			mockClient := client.NewMockSpireClient(ctrl)
			mockClient.EXPECT().GetCertificateForIdentity(gomock.Any()).Return(tlsCert, nil)

			if tt.includeFederated {
				mockClient.EXPECT().GetBundlesByDomain(gomock.Any()).Return(tt.bundlesByDomain, tt.getBundlesError)

				if tt.getBundlesError != nil || (tt.fallbackToRegular && !tt.mergeFederatedBundle) {
					// Expect fallback to GetCACertificates
					mockClient.EXPECT().GetCACertificates(gomock.Any()).Return([]*x509.Certificate{generateTestCACertificate(t)}, nil)
				}
			} else {
				// When not federated, always use GetCACertificates
				mockClient.EXPECT().GetCACertificates(gomock.Any()).Return([]*x509.Certificate{generateTestCACertificate(t)}, nil)
			}

			object := config.Object{
				ObjectName:           "test",
				Type:                 "x509-svid",
				Paths:                []string{"/cert.pem", "/key.pem", "/bundle.pem"},
				IncludeFederated:     tt.includeFederated,
				MergeFederatedBundle: tt.mergeFederatedBundle,
			}

			ctx := context.Background()
			result, err := provider.fetchX509SVID(ctx, mockClient, object, "spiffe://example.org/ns/default/sa/test")

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Check that all expected files are present
			for expectedPath := range tt.expectFiles {
				if _, exists := result[expectedPath]; !exists {
					t.Errorf("Expected file %s not found in result", expectedPath)
				}
			}

			// Check no unexpected files
			for resultPath := range result {
				if !tt.expectFiles[resultPath] {
					t.Errorf("Unexpected file %s in result", resultPath)
				}
			}

			// Verify all files contain valid PEM data
			for path, content := range result {
				if strings.HasSuffix(path, "bundle.pem") || path == "/cert.pem" {
					if !strings.Contains(string(content), "BEGIN CERTIFICATE") {
						t.Errorf("File %s does not contain valid certificate PEM", path)
					}
				} else if path == "/key.pem" {
					if !strings.Contains(string(content), "BEGIN PRIVATE KEY") {
						t.Errorf("File %s does not contain valid private key PEM", path)
					}
				}
			}

			// Verify certificate counts in bundles
			for path, expectedCount := range tt.verifyCertCount {
				if content, exists := result[path]; exists {
					certCount := strings.Count(string(content), "BEGIN CERTIFICATE")
					if certCount != expectedCount {
						t.Errorf("File %s: expected %d certificates, got %d", path, expectedCount, certCount)
					}
				}
			}
		})
	}
}

func TestEncodeCertificates(t *testing.T) {
	tests := []struct {
		name      string
		certCount int
		expectPEM bool
	}{
		{
			name:      "empty certificates",
			certCount: 0,
			expectPEM: false,
		},
		{
			name:      "single certificate",
			certCount: 1,
			expectPEM: true,
		},
		{
			name:      "multiple certificates",
			certCount: 3,
			expectPEM: true,
		},
		{
			name:      "nil certificates",
			certCount: -1,
			expectPEM: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			hmacGen := hmac.NewHMACGenerator([]byte("test"))
			podContext := metrics.PodContext{}
			provider := NewProviderWithContext(logger, hmacGen, podContext)

			var certs []*x509.Certificate
			if tt.certCount == -1 {
				certs = nil
			} else {
				for i := 0; i < tt.certCount; i++ {
					certs = append(certs, generateTestCACertificate(t))
				}
			}

			result := provider.encodeCertificates(certs)

			if tt.expectPEM {
				certBlocks := strings.Count(string(result), "BEGIN CERTIFICATE")
				if certBlocks != tt.certCount {
					t.Errorf("Expected %d certificate blocks, got %d", tt.certCount, certBlocks)
				}

				// Verify each block ends properly
				endBlocks := strings.Count(string(result), "END CERTIFICATE")
				if endBlocks != tt.certCount {
					t.Errorf("Expected %d END CERTIFICATE blocks, got %d", tt.certCount, endBlocks)
				}
			} else {
				if len(result) != 0 {
					t.Errorf("Expected empty result for %d certificates, got %d bytes", tt.certCount, len(result))
				}
			}
		})
	}
}

func TestExtractTrustDomain(t *testing.T) {
	tests := []struct {
		name     string
		spiffeID string
		want     string
	}{
		{
			name:     "standard SPIFFE ID",
			spiffeID: "spiffe://example.org/ns/default/sa/test",
			want:     "example.org",
		},
		{
			name:     "SPIFFE ID with subdomain",
			spiffeID: "spiffe://sub.example.org/ns/prod/sa/api",
			want:     "sub.example.org",
		},
		{
			name:     "SPIFFE ID with port",
			spiffeID: "spiffe://example.org:8080/ns/default/sa/test",
			want:     "example.org:8080",
		},
		{
			name:     "SPIFFE ID with minimal path",
			spiffeID: "spiffe://example.org/workload",
			want:     "example.org",
		},
		{
			name:     "SPIFFE ID with no path",
			spiffeID: "spiffe://example.org",
			want:     "example.org",
		},
		{
			name:     "SPIFFE ID with trailing slash",
			spiffeID: "spiffe://example.org/",
			want:     "example.org",
		},
		{
			name:     "invalid - no spiffe prefix",
			spiffeID: "example.org/ns/default/sa/test",
			want:     "",
		},
		{
			name:     "invalid - http prefix",
			spiffeID: "http://example.org/ns/default/sa/test",
			want:     "",
		},
		{
			name:     "empty SPIFFE ID",
			spiffeID: "",
			want:     "",
		},
		{
			name:     "just spiffe prefix",
			spiffeID: "spiffe://",
			want:     "",
		},
		{
			name:     "SPIFFE ID with special characters in domain",
			spiffeID: "spiffe://test-domain.example_org.com/ns/default",
			want:     "test-domain.example_org.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			hmacGen := hmac.NewHMACGenerator([]byte("test"))
			podContext := metrics.PodContext{}
			provider := NewProviderWithContext(logger, hmacGen, podContext)

			got := provider.extractTrustDomain(tt.spiffeID)
			if got != tt.want {
				t.Errorf("extractTrustDomain(%q) = %q, want %q", tt.spiffeID, got, tt.want)
			}
		})
	}
}

func TestHandleMountRequest_WithFederatedX509(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := hclog.NewNullLogger()
	hmacGen := hmac.NewHMACGenerator([]byte("test-key"))
	podContext := metrics.PodContext{
		Namespace:      "default",
		ServiceAccount: "test-sa",
		PodUID:         "123",
		PodName:        "test-pod",
	}

	cert, key := generateTestCertificate(t)
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}

	mainCert := generateTestCACertificate(t)
	partnerCert := generateTestCACertificate(t)

	bundlesByDomain := map[string][]*x509.Certificate{
		"example.org": {mainCert},
		"partner.com": {partnerCert},
	}

	mockClient := client.NewMockSpireClient(ctrl)
	mockClient.EXPECT().WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	mockClient.EXPECT().WaitForTrustBundle(gomock.Any(), gomock.Any()).Return(nil)
	mockClient.EXPECT().GetCertificateForIdentity(gomock.Any()).Return(tlsCert, nil)
	mockClient.EXPECT().GetBundlesByDomain(gomock.Any()).Return(bundlesByDomain, nil)

	mockPool := client.NewMockClientPoolInterface(ctrl)
	mockPool.EXPECT().AcquireClient(gomock.Any(), gomock.Any()).Return(mockClient, nil)
	mockPool.EXPECT().ReleaseClient(gomock.Any()).Return()

	provider := NewProviderWithClientPool(logger, hmacGen, podContext, mockPool)

	cfg := config.Config{
		TargetPath:     "/var/run/secrets",
		FilePermission: 0644,
		Parameters: config.Parameters{
			TrustDomain: "example.org",
			PodInfo: config.PodInfo{
				Namespace:          "default",
				ServiceAccountName: "test-sa",
				UID:                "123",
				Name:               "test-pod",
			},
			Selectors: []config.Selector{
				{Type: "k8s", Value: "ns:default"},
				{Type: "k8s", Value: "sa:test-sa"},
			},
			Objects: []config.Object{
				{
					ObjectName:           "x509-svid",
					Type:                 "x509-svid",
					Paths:                []string{"/tls/cert.pem", "/tls/key.pem", "/tls/bundle.pem"},
					IncludeFederated:     true,
					MergeFederatedBundle: true,
				},
			},
		},
	}

	flagsConfig := config.FlagsConfig{
		SpireSocketPath: "/run/spire/socket",
	}

	ctx := context.Background()
	resp, err := provider.HandleMountRequest(ctx, cfg, flagsConfig)

	if err != nil {
		t.Fatalf("HandleMountRequest failed: %v", err)
	}

	// Should have cert, key, and merged bundle
	if len(resp.Files) != 3 {
		t.Errorf("Expected 3 files, got %d", len(resp.Files))
	}

	// Find the bundle file and verify it contains both certificates
	for _, file := range resp.Files {
		if file.Path == "/tls/bundle.pem" {
			bundleContent := string(file.Contents)
			certCount := strings.Count(bundleContent, "BEGIN CERTIFICATE")
			if certCount != 2 {
				t.Errorf("Merged bundle should contain 2 certificates, got %d", certCount)
			}
		}
	}
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
			CommonName:   "test.example.org",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"test.example.org", "localhost"},
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

func generateTestCACertificate(t *testing.T) *x509.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

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

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
