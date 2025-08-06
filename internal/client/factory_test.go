// internal/client/factory_test.go
package client

import (
	"testing"
	"github.com/hashicorp/go-hclog"
)

func TestNewSpireClient_Factory(t *testing.T) {
	tests := []struct {
		name            string
		config          Config
		expectDualAgent bool
		expectError     bool
	}{
		{
			name: "single agent client",
			config: Config{
				SpireSocketPath:   "/socket",
				SpiffeTrustDomain: "example.org",
			},
			expectDualAgent: false,
			expectError:     false,
		},
		{
			name: "dual agent client",
			config: Config{
				SpireSocketPath:   "/socket1",
				SpireSocketPath2:  "/socket2",
				SpiffeTrustDomain: "example.org",
			},
			expectDualAgent: true,
			expectError:     false,
		},
		{
			name: "missing socket path",
			config: Config{
				SpiffeTrustDomain: "example.org",
			},
			expectError: true,
		},
		{
			name: "missing trust domain",
			config: Config{
				SpireSocketPath: "/socket",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hclog.NewNullLogger()
			
			// Call the actual factory function
			client, err := NewSpireClient(logger, tt.config)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			if client == nil {
				t.Fatal("Expected client to be created")
			}
			
			// Check the type of client returned
			switch c := client.(type) {
			case *DualAgentClient:
				if !tt.expectDualAgent {
					t.Error("Expected single agent client, got dual agent")
				}
				// Verify it has both socket paths
				if c.config.SpireSocketPath == "" || c.config.SpireSocketPath2 == "" {
					t.Error("Dual agent client should have both socket paths")
				}
			case *Client:
				if tt.expectDualAgent {
					t.Error("Expected dual agent client, got single agent")
				}
				// Verify it has only one socket path
				if c.config.SpireSocketPath == "" {
					t.Error("Single agent client should have socket path")
				}
				if c.config.SpireSocketPath2 != "" {
					t.Error("Single agent client should not have second socket path")
				}
			default:
				t.Errorf("Unexpected client type: %T", client)
			}
		})
	}
}

// Test that both New and NewDualAgentClient work correctly
func TestClientConstructors(t *testing.T) {
	logger := hclog.NewNullLogger()
	
	t.Run("New creates single agent client", func(t *testing.T) {
		config := Config{
			SpireSocketPath:   "/socket",
			SpiffeTrustDomain: "example.org",
		}
		
		client, err := New(logger, config)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		
		if client == nil {
			t.Fatal("Expected client to be created")
		}
		
		if client.config.SpireSocketPath != config.SpireSocketPath {
			t.Error("Socket path not set correctly")
		}
	})
	
	t.Run("NewDualAgentClient creates dual agent client", func(t *testing.T) {
		config := Config{
			SpireSocketPath:   "/socket1",
			SpireSocketPath2:  "/socket2",
			SpiffeTrustDomain: "example.org",
		}
		
		client, err := NewDualAgentClient(logger, config)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		
		if client == nil {
			t.Fatal("Expected client to be created")
		}
		
		if client.config.SpireSocketPath != config.SpireSocketPath {
			t.Error("First socket path not set correctly")
		}
		
		if client.config.SpireSocketPath2 != config.SpireSocketPath2 {
			t.Error("Second socket path not set correctly")
		}
	})
}
