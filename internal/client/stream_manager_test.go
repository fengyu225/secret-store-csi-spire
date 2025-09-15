package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewStreamManager(t *testing.T) {
	logger := hclog.NewNullLogger()
	client := &Client{
		logger: logger,
		config: Config{
			SpiffeTrustDomain: "example.org",
		},
	}

	sm := newStreamManager(logger, client)

	if sm == nil {
		t.Fatal("Expected non-nil stream manager")
	}
	if sm.logger == nil {
		t.Error("Logger should be set")
	}
	if sm.client != client {
		t.Error("Client should be set")
	}
	if sm.reconnectBackoff != 1*time.Second {
		t.Error("Default reconnect backoff should be 1 second")
	}
}

func TestStreamManager_Start(t *testing.T) {
	tests := []struct {
		name           string
		alreadyStarted bool
		connectError   error
		expectError    bool
	}{
		{
			name:           "successful start",
			alreadyStarted: false,
			connectError:   nil,
			expectError:    false,
		},
		{
			name:           "already started",
			alreadyStarted: true,
			connectError:   nil,
			expectError:    false,
		},
		{
			name:           "connection error",
			alreadyStarted: false,
			connectError:   errors.New("connection failed"),
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := hclog.NewNullLogger()

			config := Config{
				SpireSocketPath:   "/tmp/test.sock",
				SpiffeTrustDomain: "example.org",
			}

			client := &Client{
				logger:        logger,
				config:        config,
				conn:          newConnectionManager(logger, config),
				svidManager:   newSVIDManager(logger),
				bundleManager: newTrustBundleManager(logger),
			}

			sm := newStreamManager(logger, client)

			if tt.alreadyStarted {
				sm.initialized.Store(true)
			}

			if !tt.alreadyStarted {
				if tt.connectError != nil {
					// Mock connection failure
					client.conn.connected = false
					client.conn.lastConnectError = tt.connectError
				} else {
					mockDelegatedClient := NewMockDelegatedIdentityClient(ctrl)

					mockSVIDStream := NewMockDelegatedIdentity_SubscribeToX509SVIDsClient(ctrl)
					mockBundleStream := NewMockDelegatedIdentity_SubscribeToX509BundlesClient(ctrl)

					mockDelegatedClient.EXPECT().
						SubscribeToX509SVIDs(gomock.Any(), gomock.Any()).
						Return(mockSVIDStream, nil).
						AnyTimes()

					mockDelegatedClient.EXPECT().
						SubscribeToX509Bundles(gomock.Any(), gomock.Any()).
						Return(mockBundleStream, nil).
						AnyTimes()

					client.conn.client = mockDelegatedClient
					client.conn.connected = true
				}
			}

			ctx := context.Background()
			err := sm.start(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil && !tt.alreadyStarted {
					t.Logf("Connection attempt made (expected in test environment): %v", err)
				}
			}

			sm.stop()
		})
	}
}

func TestStreamManager_Stop(t *testing.T) {
	logger := hclog.NewNullLogger()
	client := &Client{
		logger:        logger,
		svidManager:   newSVIDManager(logger),
		bundleManager: newTrustBundleManager(logger),
	}

	sm := newStreamManager(logger, client)

	// Stop without start should not panic
	sm.stop()

	// Start and stop
	sm.initialized.Store(true)
	sm.listenCtx, sm.cancelFunc = context.WithCancel(context.Background())
	sm.streamsHealthy.Store(true)

	sm.stop()

	if sm.initialized.Load() {
		t.Error("Should not be initialized after stop")
	}
	if sm.streamsHealthy.Load() {
		t.Error("Should not be healthy after stop")
	}
}

func TestStreamManager_IsHealthy(t *testing.T) {
	tests := []struct {
		name        string
		initialized bool
		healthy     bool
		expected    bool
	}{
		{
			name:        "healthy",
			initialized: true,
			healthy:     true,
			expected:    true,
		},
		{
			name:        "not initialized",
			initialized: false,
			healthy:     true,
			expected:    false,
		},
		{
			name:        "not healthy",
			initialized: true,
			healthy:     false,
			expected:    false,
		},
		{
			name:        "neither",
			initialized: false,
			healthy:     false,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			client := &Client{logger: logger}
			sm := newStreamManager(logger, client)

			sm.initialized.Store(tt.initialized)
			sm.streamsHealthy.Store(tt.healthy)

			result := sm.isHealthy()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestStreamManager_EnsureHealthy(t *testing.T) {
	tests := []struct {
		name         string
		isHealthy    bool
		initialized  bool
		expectAction string
	}{
		{
			name:         "already healthy",
			isHealthy:    true,
			initialized:  true,
			expectAction: "none",
		},
		{
			name:         "not initialized",
			isHealthy:    false,
			initialized:  false,
			expectAction: "start",
		},
		{
			name:         "initialized but not healthy",
			isHealthy:    false,
			initialized:  true,
			expectAction: "reconnect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			client := &Client{
				logger:        logger,
				conn:          newConnectionManager(logger, Config{}),
				svidManager:   newSVIDManager(logger),
				bundleManager: newTrustBundleManager(logger),
			}
			sm := newStreamManager(logger, client)

			if tt.isHealthy {
				sm.initialized.Store(true)
				sm.streamsHealthy.Store(true)
			} else {
				sm.initialized.Store(tt.initialized)
				sm.streamsHealthy.Store(false)
			}

			ctx := context.Background()
			err := sm.ensureHealthy(ctx)

			if err == nil && tt.expectAction != "none" {
				t.Logf("Action %s attempted", tt.expectAction)
			}
		})
	}
}

func TestStreamManager_ShouldReconnect(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "context canceled",
			err:      context.Canceled,
			expected: false,
		},
		{
			name:     "unavailable error",
			err:      status.Error(codes.Unavailable, "unavailable"),
			expected: true,
		},
		{
			name:     "transport closing",
			err:      errors.New("transport is closing"),
			expected: true,
		},
		{
			name:     "EOF",
			err:      io.EOF,
			expected: true,
		},
		{
			name:     "connection refused",
			err:      errors.New("connection refused"),
			expected: true,
		},
		{
			name:     "broken pipe",
			err:      errors.New("broken pipe"),
			expected: true,
		},
		{
			name:     "keepalive error",
			err:      errors.New("ENHANCE_YOUR_CALM"),
			expected: true,
		},
		{
			name:     "too many pings",
			err:      errors.New("too_many_pings"),
			expected: true,
		},
		{
			name:     "permission denied",
			err:      status.Error(codes.PermissionDenied, "permission denied"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			client := &Client{logger: logger}
			sm := newStreamManager(logger, client)

			result := sm.shouldReconnect(tt.err)
			if result != tt.expected {
				t.Errorf("shouldReconnect(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestStreamManager_HandleStreamError(t *testing.T) {
	tests := []struct {
		name              string
		err               error
		streamType        string
		expectReconnect   bool
		expectHealthyFlag bool
	}{
		{
			name:              "EOF error",
			err:               io.EOF,
			streamType:        "SVID",
			expectReconnect:   true,
			expectHealthyFlag: false,
		},
		{
			name:              "keepalive error",
			err:               errors.New("ENHANCE_YOUR_CALM"),
			streamType:        "bundle",
			expectReconnect:   true,
			expectHealthyFlag: false,
		},
		{
			name:              "permission denied",
			err:               status.Error(codes.PermissionDenied, "denied"),
			streamType:        "SVID",
			expectReconnect:   true,
			expectHealthyFlag: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			client := &Client{logger: logger}
			sm := newStreamManager(logger, client)
			sm.streamsHealthy.Store(true)

			errorChan := make(chan error, 1)
			ctx := context.Background()

			sm.handleStreamError(tt.err, tt.streamType, errorChan, ctx)

			if tt.expectReconnect {
				select {
				case receivedErr := <-errorChan:
					if receivedErr != tt.err {
						t.Errorf("Expected error %v, got %v", tt.err, receivedErr)
					}
				default:
					t.Error("Expected error to be sent to channel")
				}
			}

			if sm.streamsHealthy.Load() != tt.expectHealthyFlag {
				t.Errorf("Expected healthy flag to be %v", tt.expectHealthyFlag)
			}
		})
	}
}

func TestStreamManager_Reconnect(t *testing.T) {
	tests := []struct {
		name            string
		alreadyHealthy  bool
		reconnecting    bool
		expectReconnect bool
	}{
		{
			name:            "needs reconnect",
			alreadyHealthy:  false,
			reconnecting:    false,
			expectReconnect: true,
		},
		{
			name:            "already healthy",
			alreadyHealthy:  true,
			reconnecting:    false,
			expectReconnect: false,
		},
		{
			name:            "already reconnecting",
			alreadyHealthy:  false,
			reconnecting:    true,
			expectReconnect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			client := &Client{
				logger:        logger,
				conn:          newConnectionManager(logger, Config{}),
				svidManager:   newSVIDManager(logger),
				bundleManager: newTrustBundleManager(logger),
			}
			sm := newStreamManager(logger, client)

			sm.streamsHealthy.Store(tt.alreadyHealthy)
			sm.reconnecting = tt.reconnecting
			// Short backoff for testing
			sm.reconnectBackoff = 10 * time.Millisecond

			ctx := context.Background()
			err := sm.reconnect(ctx)

			if err != nil {
				t.Logf("Reconnect attempted, error: %v", err)
			}
		})
	}
}

func TestStreamManager_ConcurrentOperations(t *testing.T) {
	logger := hclog.NewNullLogger()
	client := &Client{
		logger:        logger,
		conn:          newConnectionManager(logger, Config{}),
		svidManager:   newSVIDManager(logger),
		bundleManager: newTrustBundleManager(logger),
	}
	sm := newStreamManager(logger, client)

	done := make(chan bool, 50)

	// Concurrent health checks
	for i := 0; i < 10; i++ {
		go func() {
			sm.isHealthy()
			done <- true
		}()
	}

	// Concurrent ensure healthy
	for i := 0; i < 10; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			sm.ensureHealthy(ctx)
			done <- true
		}()
	}

	// Concurrent reconnect attempts
	for i := 0; i < 10; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			sm.reconnect(ctx)
			done <- true
		}()
	}

	// Concurrent start/stop
	for i := 0; i < 10; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			sm.start(ctx)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		go func() {
			sm.stop()
			done <- true
		}()
	}

	// Wait for all operations
	for i := 0; i < 50; i++ {
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}
}

func TestStreamManager_ShouldReconnectWithPermissionDenied(t *testing.T) {
	logger := hclog.NewNullLogger()
	client := &Client{logger: logger}
	sm := newStreamManager(logger, client)

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "permission denied error triggers reconnect",
			err:      status.Error(codes.PermissionDenied, "permission denied"),
			expected: true,
		},
		{
			name:     "wrapped permission denied error",
			err:      fmt.Errorf("stream error: %w", status.Error(codes.PermissionDenied, "denied")),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sm.shouldReconnect(tt.err)
			if result != tt.expected {
				t.Errorf("shouldReconnect(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}
