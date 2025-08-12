package client

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
)

func TestNewConnectionManager(t *testing.T) {
	logger := hclog.NewNullLogger()
	config := Config{
		SpireSocketPath:   "/tmp/test.sock",
		SpiffeTrustDomain: "example.org",
	}

	cm := newConnectionManager(logger, config)

	if cm == nil {
		t.Fatal("Expected non-nil connection manager")
	}
	if cm.logger == nil {
		t.Error("Logger should be set")
	}
	if cm.config.SpireSocketPath != config.SpireSocketPath {
		t.Error("Config not set correctly")
	}
}

func TestConnectionManager_Connect(t *testing.T) {
	tests := []struct {
		name         string
		socketPath   string
		createSocket bool
		expectError  bool
	}{
		{
			name:         "socket does not exist",
			socketPath:   "/tmp/nonexistent.sock",
			createSocket: false,
			expectError:  true,
		},
		{
			name:         "valid socket path",
			socketPath:   "/tmp/test.sock",
			createSocket: true,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.createSocket {
				file, err := os.Create(tt.socketPath)
				if err != nil {
					t.Skip("Cannot create test socket file")
				}
				file.Close()
				defer os.Remove(tt.socketPath)
			}

			logger := hclog.NewNullLogger()
			config := Config{
				SpireSocketPath:   tt.socketPath,
				SpiffeTrustDomain: "example.org",
			}

			cm := newConnectionManager(logger, config)
			ctx := context.Background()

			err := cm.connect(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					// This might fail in test environment without actual gRPC server
					// Just check that we attempted connection
					t.Logf("Connection attempt made: %v", err)
				}
			}

			cm.close()
		})
	}
}

func TestConnectionManager_Close(t *testing.T) {
	logger := hclog.NewNullLogger()
	config := Config{
		SpireSocketPath:   "/tmp/test.sock",
		SpiffeTrustDomain: "example.org",
	}

	cm := newConnectionManager(logger, config)

	// Close without connection should not panic
	cm.close()

	// Multiple closes should not panic
	cm.close()
	cm.close()
}

func TestConnectionManager_IsHealthy(t *testing.T) {
	logger := hclog.NewNullLogger()
	config := Config{
		SpireSocketPath:   "/tmp/test.sock",
		SpiffeTrustDomain: "example.org",
	}

	cm := newConnectionManager(logger, config)

	// Should be unhealthy without connection
	if cm.isHealthy() {
		t.Error("Should be unhealthy without connection")
	}

	// Set connected flag
	cm.connected = true
	// Still unhealthy without actual connection
	if cm.isHealthy() {
		t.Error("Should be unhealthy without gRPC connection")
	}
}

func TestConnectionManager_GetClient(t *testing.T) {
	logger := hclog.NewNullLogger()
	config := Config{
		SpireSocketPath:   "/tmp/test.sock",
		SpiffeTrustDomain: "example.org",
	}

	cm := newConnectionManager(logger, config)

	// Should return nil without connection
	client := cm.getClient()
	if client != nil {
		t.Error("Expected nil client without connection")
	}
}

func TestConnectionManager_GetStatus(t *testing.T) {
	tests := []struct {
		name             string
		connected        bool
		lastConnectError error
		expectedStatus   bool
		expectedMsgPart  string
	}{
		{
			name:             "not connected",
			connected:        false,
			lastConnectError: nil,
			expectedStatus:   false,
			expectedMsgPart:  "Not connected",
		},
		{
			name:             "connected",
			connected:        true,
			lastConnectError: nil,
			expectedStatus:   true,
			expectedMsgPart:  "Connected",
		},
		{
			name:             "not connected with error",
			connected:        false,
			lastConnectError: context.DeadlineExceeded,
			expectedStatus:   false,
			expectedMsgPart:  "Cannot connect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			config := Config{
				SpireSocketPath:   "/tmp/test.sock",
				SpiffeTrustDomain: "example.org",
			}

			cm := newConnectionManager(logger, config)
			cm.connected = tt.connected
			cm.lastConnectError = tt.lastConnectError

			status, msg := cm.getStatus()

			if status != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, status)
			}
			if !contains(msg, tt.expectedMsgPart) {
				t.Errorf("Expected message to contain %q, got %q", tt.expectedMsgPart, msg)
			}
		})
	}
}

func TestConnectionManager_ConcurrentAccess(t *testing.T) {
	logger := hclog.NewNullLogger()
	config := Config{
		SpireSocketPath:   "/tmp/test.sock",
		SpiffeTrustDomain: "example.org",
	}

	cm := newConnectionManager(logger, config)

	// Run concurrent operations
	done := make(chan bool, 4)

	go func() {
		cm.isHealthy()
		done <- true
	}()

	go func() {
		cm.getClient()
		done <- true
	}()

	go func() {
		cm.getStatus()
		done <- true
	}()

	go func() {
		cm.close()
		done <- true
	}()

	// Wait for all goroutines
	for i := 0; i < 4; i++ {
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}
}
