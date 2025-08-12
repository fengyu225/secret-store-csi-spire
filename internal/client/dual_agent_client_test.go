package client

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/go-hclog"
)

func TestNewDualAgentClient(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid dual agent config",
			config: Config{
				SpireSocketPath:   "/socket1",
				SpireSocketPath2:  "/socket2",
				SpiffeTrustDomain: "example.org",
			},
			wantErr: false,
		},
		{
			name: "missing second socket path",
			config: Config{
				SpireSocketPath:   "/socket1",
				SpiffeTrustDomain: "example.org",
			},
			wantErr: true,
			errMsg:  "second socket path is required",
		},
		{
			name: "missing first socket path",
			config: Config{
				SpireSocketPath2:  "/socket2",
				SpiffeTrustDomain: "example.org",
			},
			wantErr: true,
			errMsg:  "SPIRE socket path not specified",
		},
		{
			name: "missing trust domain",
			config: Config{
				SpireSocketPath:  "/socket1",
				SpireSocketPath2: "/socket2",
			},
			wantErr: true,
			errMsg:  "SPIRE trust domain not specified",
		},
		{
			name: "identical socket paths",
			config: Config{
				SpireSocketPath:   "/same/socket",
				SpireSocketPath2:  "/same/socket",
				SpiffeTrustDomain: "example.org",
			},
			wantErr: true,
			errMsg:  "socket paths must be different for dual agent redundancy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()

			client, err := NewDualAgentClient(logger, tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if client == nil {
					t.Error("Expected client to be created")
				} else {
					// Verify both clients are initialized
					if client.client1 == nil || client.client2 == nil {
						t.Error("Both clients should be initialized")
					}
					// Verify configs are set correctly
					if client.config.SpireSocketPath != tt.config.SpireSocketPath {
						t.Error("First socket path not set correctly")
					}
					if client.config.SpireSocketPath2 != tt.config.SpireSocketPath2 {
						t.Error("Second socket path not set correctly")
					}
				}
			}
		})
	}
}

func TestDualAgentClient_Start(t *testing.T) {
	tests := []struct {
		name         string
		client1Error error
		client2Error error
		expectError  bool
	}{
		{
			name:        "both clients start successfully",
			expectError: false,
		},
		{
			name:         "client1 fails",
			client1Error: errors.New("client1 start failed"),
			expectError:  false,
		},
		{
			name:         "client2 fails",
			client2Error: errors.New("client2 start failed"),
			expectError:  false,
		},
		{
			name:         "both clients fail",
			client1Error: errors.New("client1 start failed"),
			client2Error: errors.New("client2 start failed"),
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()

			mockClient1 := NewMockSpireClient(ctrl)
			mockClient1.EXPECT().Start(gomock.Any()).Return(tt.client1Error)

			mockClient2 := NewMockSpireClient(ctrl)
			mockClient2.EXPECT().Start(gomock.Any()).Return(tt.client2Error)

			dac := &DualAgentClient{
				logger:  logger,
				client1: mockClient1,
				client2: mockClient2,
			}

			ctx := context.Background()
			err := dac.Start(ctx)

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

func TestDualAgentClient_WaitForSVID(t *testing.T) {
	tests := []struct {
		name         string
		client1Error error
		client2Error error
		expectError  bool
	}{
		{
			name:        "client1 succeeds",
			expectError: false,
		},
		{
			name:         "client1 fails, client2 succeeds",
			client1Error: errors.New("client1 failed"),
			expectError:  false,
		},
		{
			name:         "both clients fail",
			client1Error: errors.New("client1 failed"),
			client2Error: errors.New("client2 failed"),
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()

			mockClient1 := NewMockSpireClient(ctrl)
			mockClient2 := NewMockSpireClient(ctrl)

			mockClient1.EXPECT().
				WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx context.Context, spiffeID string, timeout time.Duration) error {
					// Simulate some processing time
					select {
					case <-time.After(10 * time.Millisecond):
						return tt.client1Error
					case <-ctx.Done():
						return ctx.Err()
					}
				}).
				AnyTimes()

			mockClient2.EXPECT().
				WaitForSVID(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx context.Context, spiffeID string, timeout time.Duration) error {
					// Simulate some processing time
					select {
					case <-time.After(10 * time.Millisecond):
						return tt.client2Error
					case <-ctx.Done():
						return ctx.Err()
					}
				}).
				AnyTimes()

			dac := &DualAgentClient{
				logger:  logger,
				client1: mockClient1,
				client2: mockClient2,
			}

			ctx := context.Background()
			err := dac.WaitForSVID(ctx, "spiffe://example.org/test", 1*time.Second)

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

func TestDualAgentClient_GetCertificateForIdentity(t *testing.T) {
	logger := hclog.NewNullLogger()

	cert := &tls.Certificate{
		Certificate: [][]byte{[]byte("test-cert")},
	}

	tests := []struct {
		name          string
		client1Return *tls.Certificate
		client1Error  error
		client2Return *tls.Certificate
		client2Error  error
		expectError   bool
	}{
		{
			name:          "client1 returns certificate",
			client1Return: cert,
			expectError:   false,
		},
		{
			name:          "client1 fails, client2 succeeds",
			client1Error:  errors.New("client1 failed"),
			client2Return: cert,
			expectError:   false,
		},
		{
			name:         "both clients fail",
			client1Error: errors.New("client1 failed"),
			client2Error: errors.New("client2 failed"),
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient1 := NewMockSpireClient(ctrl)
			mockClient2 := NewMockSpireClient(ctrl)

			mockClient1.EXPECT().
				GetCertificateForIdentity(gomock.Any()).
				Return(tt.client1Return, tt.client1Error).
				AnyTimes()

			mockClient2.EXPECT().
				GetCertificateForIdentity(gomock.Any()).
				Return(tt.client2Return, tt.client2Error).
				AnyTimes()

			dac := &DualAgentClient{
				logger:  logger,
				client1: mockClient1,
				client2: mockClient2,
			}

			result, err := dac.GetCertificateForIdentity("spiffe://example.org/test")

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Error("Expected certificate but got nil")
				}
			}
		})
	}
}

func TestDualAgentClient_FetchJWTSVID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := hclog.NewNullLogger()

	tests := []struct {
		name         string
		client1Token string
		client1Error error
		client2Token string
		client2Error error
		expectError  bool
		expectToken  string
	}{
		{
			name:         "client1 returns token",
			client1Token: "token-from-client1",
			expectToken:  "token-from-client1",
			expectError:  false,
		},
		{
			name:         "client1 fails, client2 succeeds",
			client1Error: errors.New("client1 failed"),
			client2Token: "token-from-client2",
			expectToken:  "token-from-client2",
			expectError:  false,
		},
		{
			name:         "both clients fail",
			client1Error: errors.New("client1 failed"),
			client2Error: errors.New("client2 failed"),
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient1 := NewMockSpireClient(ctrl)
			mockClient1.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(tt.client1Token, tt.client1Error)

			mockClient2 := NewMockSpireClient(ctrl)
			mockClient2.EXPECT().FetchJWTSVID(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(tt.client2Token, tt.client2Error)

			dac := &DualAgentClient{
				logger:  logger,
				client1: mockClient1,
				client2: mockClient2,
			}

			ctx := context.Background()
			token, err := dac.FetchJWTSVID(ctx, "spiffe://example.org/test", []string{"audience1"})

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if token != tt.expectToken {
					t.Errorf("Expected token %q, got %q", tt.expectToken, token)
				}
			}
		})
	}
}

func TestDualAgentClient_Status(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tests := []struct {
		name            string
		client1Status   bool
		client1Msg      string
		client2Status   bool
		client2Msg      string
		expectedStatus  bool
		expectedMsgPart string
	}{
		{
			name:            "both connected",
			client1Status:   true,
			client1Msg:      "Connected",
			client2Status:   true,
			client2Msg:      "Connected",
			expectedStatus:  true,
			expectedMsgPart: "Both agents connected",
		},
		{
			name:            "only client1 connected",
			client1Status:   true,
			client1Msg:      "Connected",
			client2Status:   false,
			client2Msg:      "Not connected",
			expectedStatus:  true,
			expectedMsgPart: "Agent1 connected",
		},
		{
			name:            "only client2 connected",
			client1Status:   false,
			client1Msg:      "Not connected",
			client2Status:   true,
			client2Msg:      "Connected",
			expectedStatus:  true,
			expectedMsgPart: "Agent2 connected",
		},
		{
			name:            "both disconnected",
			client1Status:   false,
			client1Msg:      "Connection failed",
			client2Status:   false,
			client2Msg:      "Connection failed",
			expectedStatus:  false,
			expectedMsgPart: "Both agents disconnected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient1 := NewMockSpireClient(ctrl)
			mockClient1.EXPECT().Status().Return(tt.client1Status, tt.client1Msg)

			mockClient2 := NewMockSpireClient(ctrl)
			mockClient2.EXPECT().Status().Return(tt.client2Status, tt.client2Msg)

			dac := &DualAgentClient{
				logger:  hclog.NewNullLogger(),
				client1: mockClient1,
				client2: mockClient2,
			}

			status, msg := dac.Status()

			if status != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, status)
			}
			if !contains(msg, tt.expectedMsgPart) {
				t.Errorf("Expected message containing %q, got %q", tt.expectedMsgPart, msg)
			}
		})
	}
}

func TestDualAgentClient_Stop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tests := []struct {
		name         string
		client1Error error
		client2Error error
		expectError  bool
	}{
		{
			name:        "both clients stop successfully",
			expectError: false,
		},
		{
			name:         "client1 fails to stop",
			client1Error: errors.New("stop failed"),
			expectError:  true,
		},
		{
			name:         "client2 fails to stop",
			client2Error: errors.New("stop failed"),
			expectError:  true,
		},
		{
			name:         "both clients fail to stop",
			client1Error: errors.New("client1 stop failed"),
			client2Error: errors.New("client2 stop failed"),
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient1 := NewMockSpireClient(ctrl)
			mockClient1.EXPECT().Stop().Return(tt.client1Error)

			mockClient2 := NewMockSpireClient(ctrl)
			mockClient2.EXPECT().Stop().Return(tt.client2Error)

			dac := &DualAgentClient{
				logger:  hclog.NewNullLogger(),
				client1: mockClient1,
				client2: mockClient2,
			}

			err := dac.Stop()

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
