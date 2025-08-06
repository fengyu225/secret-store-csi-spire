// internal/hmac/hmac_test.go
package hmac

import (
	"context"
	"encoding/base64"
	"testing"

	"spire-csi-provider/internal/config"
)

func TestNewHMACGenerator(t *testing.T) {
	tests := []struct {
		name      string
		staticKey []byte
		wantKey   []byte
	}{
		{
			name:      "with custom key",
			staticKey: []byte("custom-key-12345"),
			wantKey:   []byte("custom-key-12345"),
		},
		{
			name:      "with nil key uses default",
			staticKey: nil,
			wantKey:   []byte("spire-csi-provider-static-hmac-key-12345"),
		},
		{
			name:      "with empty key uses default",
			staticKey: []byte{},
			wantKey:   []byte("spire-csi-provider-static-hmac-key-12345"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewHMACGenerator(tt.staticKey)
			if gen == nil {
				t.Fatal("NewHMACGenerator returned nil")
			}
			
			key, err := gen.GetOrCreateHMACKey(context.Background())
			if err != nil {
				t.Fatalf("GetOrCreateHMACKey() error = %v", err)
			}
			
			if string(key) != string(tt.wantKey) {
				t.Errorf("GetOrCreateHMACKey() = %v, want %v", key, tt.wantKey)
			}
		})
	}
}

func TestGenerateObjectVersion(t *testing.T) {
	gen := NewHMACGenerator([]byte("test-key"))

	tests := []struct {
		name    string
		object  config.Object
		content []byte
		wantErr bool
	}{
		{
			name: "x509-svid object",
			object: config.Object{
				ObjectName: "test-x509",
				Type:       "x509-svid",
				Paths:      []string{"/cert", "/key", "/bundle"},
			},
			content: []byte("test-content"),
			wantErr: false,
		},
		{
			name: "jwt-svid object",
			object: config.Object{
				ObjectName: "test-jwt",
				Type:       "jwt-svid",
				Audience:   []string{"audience1"},
				Paths:      []string{"/token"},
			},
			content: []byte("jwt-token-content"),
			wantErr: false,
		},
		{
			name: "empty content",
			object: config.Object{
				ObjectName: "test-empty",
				Type:       "x509-svid",
				Paths:      []string{"/cert", "/key", "/bundle"},
			},
			content: []byte{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := gen.GenerateObjectVersion(tt.object, tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateObjectVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if version == nil {
					t.Fatal("GenerateObjectVersion() returned nil version")
				}
				if version.Id != tt.object.ObjectName {
					t.Errorf("Version.Id = %v, want %v", version.Id, tt.object.ObjectName)
				}
				if version.Version == "" {
					t.Error("Version.Version is empty")
				}
				// Verify it's a valid base64
				_, err := base64.URLEncoding.DecodeString(version.Version)
				if err != nil {
					t.Errorf("Version.Version is not valid base64: %v", err)
				}
			}
		})
	}
}

func TestGenerateObjectVersion_Deterministic(t *testing.T) {
	gen := NewHMACGenerator([]byte("test-key"))
	
	object := config.Object{
		ObjectName: "test-object",
		Type:       "x509-svid",
		Paths:      []string{"/cert", "/key", "/bundle"},
	}
	content := []byte("test-content")

	// Generate version multiple times
	version1, err1 := gen.GenerateObjectVersion(object, content)
	if err1 != nil {
		t.Fatalf("First GenerateObjectVersion() error = %v", err1)
	}

	version2, err2 := gen.GenerateObjectVersion(object, content)
	if err2 != nil {
		t.Fatalf("Second GenerateObjectVersion() error = %v", err2)
	}

	// Versions should be identical for same input
	if version1.Version != version2.Version {
		t.Errorf("HMAC not deterministic: %v != %v", version1.Version, version2.Version)
	}
}

func TestGenerateObjectVersion_DifferentContent(t *testing.T) {
	gen := NewHMACGenerator([]byte("test-key"))
	
	object := config.Object{
		ObjectName: "test-object",
		Type:       "x509-svid",
		Paths:      []string{"/cert", "/key", "/bundle"},
	}

	version1, _ := gen.GenerateObjectVersion(object, []byte("content1"))
	version2, _ := gen.GenerateObjectVersion(object, []byte("content2"))

	// Versions should be different for different content
	if version1.Version == version2.Version {
		t.Error("HMAC should differ for different content")
	}
}

func TestGenerateObjectVersion_DifferentObjects(t *testing.T) {
	gen := NewHMACGenerator([]byte("test-key"))
	
	object1 := config.Object{
		ObjectName: "object1",
		Type:       "x509-svid",
		Paths:      []string{"/cert", "/key", "/bundle"},
	}
	
	object2 := config.Object{
		ObjectName: "object2",
		Type:       "x509-svid",
		Paths:      []string{"/cert", "/key", "/bundle"},
	}
	
	content := []byte("same-content")

	version1, _ := gen.GenerateObjectVersion(object1, content)
	version2, _ := gen.GenerateObjectVersion(object2, content)

	// Versions should be different for different objects
	if version1.Version == version2.Version {
		t.Error("HMAC should differ for different objects")
	}
}

func TestGenerateObjectVersion_NilStaticKey(t *testing.T) {
	gen := &HMACGenerator{
		staticKey: nil,
	}

	object := config.Object{
		ObjectName: "test",
		Type:       "x509-svid",
		Paths:      []string{"/test"},
	}

	_, err := gen.GenerateObjectVersion(object, []byte("content"))
	if err == nil {
		t.Error("Expected error with nil static key")
	}
	if err.Error() != "no static hmac key provided" {
		t.Errorf("Unexpected error: %v", err)
	}
}
