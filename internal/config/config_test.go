package config

import (
	"encoding/json"
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name          string
		parametersStr string
		targetPath    string
		permissionStr string
		want          Config
		wantErr       bool
		errorContains string
	}{
		{
			name: "valid configuration with x509-svid",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "default",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"objects": `
- objectName: x509-svid
  type: x509-svid
  filePermission: 0644
  paths:
    - /cert.pem
    - /key.pem
    - /bundle.pem`,
			}),
			targetPath: "/var/run/secrets",
			// 0644 in decimal
			permissionStr: "420",
			want: Config{
				TargetPath:     "/var/run/secrets",
				FilePermission: 0644,
				Parameters: Parameters{
					UseCase:     "default",
					TrustDomain: "example.org",
					Selectors: []Selector{
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "sa:test-sa"},
						{Type: "k8s", Value: "pod-uid:123-456"},
					},
					Objects: []Object{
						{
							ObjectName:     "x509-svid",
							Type:           "x509-svid",
							FilePermission: 0644,
							Paths:          []string{"/cert.pem", "/key.pem", "/bundle.pem"},
						},
					},
					PodInfo: PodInfo{
						Name:               "test-pod",
						UID:                "123-456",
						Namespace:          "default",
						ServiceAccountName: "test-sa",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid configuration with jwt-svid",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "jwt",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"objects": `
- objectName: jwt-svid
  type: jwt-svid
  audience:
    - audience1
    - audience2
  paths:
    - /token.jwt`,
			}),
			targetPath:    "/var/run/secrets",
			permissionStr: "420",
			want: Config{
				TargetPath:     "/var/run/secrets",
				FilePermission: 0644,
				Parameters: Parameters{
					UseCase:     "jwt",
					TrustDomain: "example.org",
					Selectors: []Selector{
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "sa:test-sa"},
						{Type: "k8s", Value: "pod-uid:123-456"},
					},
					Objects: []Object{
						{
							ObjectName: "jwt-svid",
							Type:       "jwt-svid",
							Audience:   []string{"audience1", "audience2"},
							Paths:      []string{"/token.jwt"},
						},
					},
					PodInfo: PodInfo{
						Name:               "test-pod",
						UID:                "123-456",
						Namespace:          "default",
						ServiceAccountName: "test-sa",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple objects",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "mixed",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"objects": `
- objectName: x509-svid
  type: x509-svid
  paths:
    - /cert.pem
    - /key.pem
    - /bundle.pem
- objectName: jwt-svid
  type: jwt-svid
  audience:
    - audience1
  paths:
    - /token.jwt`,
			}),
			targetPath:    "/var/run/secrets",
			permissionStr: "420",
			want: Config{
				TargetPath:     "/var/run/secrets",
				FilePermission: 0644,
				Parameters: Parameters{
					UseCase:     "mixed",
					TrustDomain: "example.org",
					Selectors: []Selector{
						{Type: "k8s", Value: "ns:default"},
						{Type: "k8s", Value: "sa:test-sa"},
						{Type: "k8s", Value: "pod-uid:123-456"},
					},
					Objects: []Object{
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
					PodInfo: PodInfo{
						Name:               "test-pod",
						UID:                "123-456",
						Namespace:          "default",
						ServiceAccountName: "test-sa",
					},
				},
			},
			wantErr: false,
		},
		{
			name:          "invalid JSON parameters",
			parametersStr: "not-valid-json",
			targetPath:    "/var/run/secrets",
			permissionStr: "420",
			wantErr:       true,
			errorContains: "invalid character",
		},
		{
			name: "invalid YAML objects",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "default",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"objects":                                `not valid yaml`,
			}),
			targetPath:    "/var/run/secrets",
			permissionStr: "420",
			wantErr:       true,
			errorContains: "failed to parse objects",
		},
		{
			name: "missing target path",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "default",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"objects": `
- objectName: x509-svid
  type: x509-svid
  paths:
    - /cert.pem
    - /key.pem
    - /bundle.pem`,
			}),
			targetPath:    "",
			permissionStr: "420",
			wantErr:       true,
			errorContains: "missing target path",
		},
		{
			name: "no objects configured",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "default",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
			}),
			targetPath:    "/var/run/secrets",
			permissionStr: "420",
			wantErr:       true,
			errorContains: "no objects configured",
		},
		{
			name: "duplicate object names",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "default",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"objects": `
- objectName: duplicate
  type: x509-svid
  paths:
    - /cert1.pem
    - /key1.pem
    - /bundle1.pem
- objectName: duplicate
  type: x509-svid
  paths:
    - /cert2.pem
    - /key2.pem
    - /bundle2.pem`,
			}),
			targetPath:    "/var/run/secrets",
			permissionStr: "420",
			wantErr:       true,
			errorContains: "must be unique",
		},
		{
			name: "invalid object type",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "default",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"objects": `
- objectName: invalid
  type: invalid-type
  paths:
    - /test.txt`,
			}),
			targetPath:    "/var/run/secrets",
			permissionStr: "420",
			wantErr:       true,
			errorContains: "invalid type",
		},
		{
			name: "jwt-svid without audience",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "jwt",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"objects": `
- objectName: jwt-svid
  type: jwt-svid
  paths:
    - /token.jwt`,
			}),
			targetPath:    "/var/run/secrets",
			permissionStr: "420",
			wantErr:       true,
			errorContains: "audience is required",
		},
		{
			name: "object without paths",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "default",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"objects": `
- objectName: no-paths
  type: x509-svid`,
			}),
			targetPath:    "/var/run/secrets",
			permissionStr: "420",
			wantErr:       true,
			errorContains: "no paths defined",
		},
		{
			name: "x509-svid with wrong number of paths",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "default",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"objects": `
- objectName: wrong-paths
  type: x509-svid
  paths:
    - /cert.pem
    - /key.pem`,
			}),
			targetPath:    "/var/run/secrets",
			permissionStr: "420",
			wantErr:       true,
			errorContains: "should have exactly 3 paths",
		},
		{
			name: "jwt-svid with wrong number of paths",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "jwt",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"objects": `
- objectName: wrong-paths
  type: jwt-svid
  audience:
    - test
  paths:
    - /token1.jwt
    - /token2.jwt`,
			}),
			targetPath:    "/var/run/secrets",
			permissionStr: "420",
			wantErr:       true,
			errorContains: "should have exactly 1 path",
		},
		{
			name: "invalid permission string",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "default",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
				"objects": `
- objectName: x509-svid
  type: x509-svid
  paths:
    - /cert.pem
    - /key.pem
    - /bundle.pem`,
			}),
			targetPath:    "/var/run/secrets",
			permissionStr: "not-a-number",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.parametersStr, tt.targetPath, tt.permissionStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errorContains != "" {
				if !contains(err.Error(), tt.errorContains) {
					t.Errorf("Parse() error = %v, should contain %v", err, tt.errorContains)
				}
				return
			}
			if !tt.wantErr {
				compareConfigs(t, got, tt.want)
			}
		})
	}
}

func TestParseParameters(t *testing.T) {
	tests := []struct {
		name          string
		parametersStr string
		want          Parameters
		wantErr       bool
	}{
		{
			name: "complete parameters",
			parametersStr: buildParametersJSON(map[string]string{
				"useCase":                                "default",
				"trustDomain":                            "example.org",
				"csi.storage.k8s.io/pod.name":            "test-pod",
				"csi.storage.k8s.io/pod.uid":             "123-456",
				"csi.storage.k8s.io/pod.namespace":       "default",
				"csi.storage.k8s.io/serviceAccount.name": "test-sa",
			}),
			want: Parameters{
				UseCase:     "default",
				TrustDomain: "example.org",
				PodInfo: PodInfo{
					Name:               "test-pod",
					UID:                "123-456",
					Namespace:          "default",
					ServiceAccountName: "test-sa",
				},
				Selectors: []Selector{
					{Type: "k8s", Value: "ns:default"},
					{Type: "k8s", Value: "sa:test-sa"},
					{Type: "k8s", Value: "pod-uid:123-456"},
				},
			},
			wantErr: false,
		},
		{
			name: "minimal parameters",
			parametersStr: buildParametersJSON(map[string]string{
				"csi.storage.k8s.io/pod.namespace":       "kube-system",
				"csi.storage.k8s.io/serviceAccount.name": "admin",
				"csi.storage.k8s.io/pod.uid":             "abc-123",
			}),
			want: Parameters{
				PodInfo: PodInfo{
					UID:                "abc-123",
					Namespace:          "kube-system",
					ServiceAccountName: "admin",
				},
				Selectors: []Selector{
					{Type: "k8s", Value: "ns:kube-system"},
					{Type: "k8s", Value: "sa:admin"},
					{Type: "k8s", Value: "pod-uid:abc-123"},
				},
			},
			wantErr: false,
		},
		{
			name:          "invalid JSON",
			parametersStr: "{invalid json}",
			wantErr:       true,
		},
		{
			name:          "empty string",
			parametersStr: "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseParameters(tt.parametersStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				compareParameters(t, got, tt.want)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name          string
		config        Config
		wantErr       bool
		errorContains string
	}{
		{
			name: "valid config",
			config: Config{
				TargetPath:     "/var/run/secrets",
				FilePermission: 0644,
				Parameters: Parameters{
					Objects: []Object{
						{
							ObjectName: "x509",
							Type:       "x509-svid",
							Paths:      []string{"/cert", "/key", "/bundle"},
						},
					},
					Selectors: []Selector{
						{Type: "k8s", Value: "ns:default"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty target path",
			config: Config{
				TargetPath: "",
				Parameters: Parameters{
					Objects: []Object{
						{
							ObjectName: "x509",
							Type:       "x509-svid",
							Paths:      []string{"/cert", "/key", "/bundle"},
						},
					},
					Selectors: []Selector{
						{Type: "k8s", Value: "ns:default"},
					},
				},
			},
			wantErr:       true,
			errorContains: "missing target path",
		},
		{
			name: "empty selector type",
			config: Config{
				TargetPath: "/path",
				Parameters: Parameters{
					Objects: []Object{
						{
							ObjectName: "x509",
							Type:       "x509-svid",
							Paths:      []string{"/cert", "/key", "/bundle"},
						},
					},
					Selectors: []Selector{
						{Type: "", Value: "ns:default"},
					},
				},
			},
			wantErr:       true,
			errorContains: "selector type cannot be empty",
		},
		{
			name: "empty selector value",
			config: Config{
				TargetPath: "/path",
				Parameters: Parameters{
					Objects: []Object{
						{
							ObjectName: "x509",
							Type:       "x509-svid",
							Paths:      []string{"/cert", "/key", "/bundle"},
						},
					},
					Selectors: []Selector{
						{Type: "k8s", Value: ""},
					},
				},
			},
			wantErr:       true,
			errorContains: "selector value cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errorContains != "" {
				if !contains(err.Error(), tt.errorContains) {
					t.Errorf("validate() error = %v, should contain %v", err, tt.errorContains)
				}
			}
		})
	}
}

func buildParametersJSON(params map[string]string) string {
	data, _ := json.Marshal(params)
	return string(data)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) >= len(substr) && contains(s[1:], substr)
}

func compareConfigs(t *testing.T, got, want Config) {
	if got.TargetPath != want.TargetPath {
		t.Errorf("TargetPath = %v, want %v", got.TargetPath, want.TargetPath)
	}
	if got.FilePermission != want.FilePermission {
		t.Errorf("FilePermission = %v, want %v", got.FilePermission, want.FilePermission)
	}
	compareParameters(t, got.Parameters, want.Parameters)
}

func compareParameters(t *testing.T, got, want Parameters) {
	if got.UseCase != want.UseCase {
		t.Errorf("UseCase = %v, want %v", got.UseCase, want.UseCase)
	}
	if got.TrustDomain != want.TrustDomain {
		t.Errorf("TrustDomain = %v, want %v", got.TrustDomain, want.TrustDomain)
	}
	if got.PodInfo.Name != want.PodInfo.Name {
		t.Errorf("PodInfo.Name = %v, want %v", got.PodInfo.Name, want.PodInfo.Name)
	}
	if got.PodInfo.UID != want.PodInfo.UID {
		t.Errorf("PodInfo.UID = %v, want %v", got.PodInfo.UID, want.PodInfo.UID)
	}
	if got.PodInfo.Namespace != want.PodInfo.Namespace {
		t.Errorf("PodInfo.Namespace = %v, want %v", got.PodInfo.Namespace, want.PodInfo.Namespace)
	}
	if got.PodInfo.ServiceAccountName != want.PodInfo.ServiceAccountName {
		t.Errorf("PodInfo.ServiceAccountName = %v, want %v", got.PodInfo.ServiceAccountName, want.PodInfo.ServiceAccountName)
	}
	if len(got.Selectors) != len(want.Selectors) {
		t.Errorf("Selectors length = %v, want %v", len(got.Selectors), len(want.Selectors))
	}
	for i := range got.Selectors {
		if i < len(want.Selectors) {
			if got.Selectors[i].Type != want.Selectors[i].Type {
				t.Errorf("Selector[%d].Type = %v, want %v", i, got.Selectors[i].Type, want.Selectors[i].Type)
			}
			if got.Selectors[i].Value != want.Selectors[i].Value {
				t.Errorf("Selector[%d].Value = %v, want %v", i, got.Selectors[i].Value, want.Selectors[i].Value)
			}
		}
	}
	if len(got.Objects) != len(want.Objects) {
		t.Errorf("Objects length = %v, want %v", len(got.Objects), len(want.Objects))
	}
	// Compare objects in detail
	for i := range got.Objects {
		if i < len(want.Objects) {
			if got.Objects[i].ObjectName != want.Objects[i].ObjectName {
				t.Errorf("Object[%d].ObjectName = %v, want %v", i, got.Objects[i].ObjectName, want.Objects[i].ObjectName)
			}
			if got.Objects[i].Type != want.Objects[i].Type {
				t.Errorf("Object[%d].Type = %v, want %v", i, got.Objects[i].Type, want.Objects[i].Type)
			}
			if got.Objects[i].FilePermission != want.Objects[i].FilePermission {
				t.Errorf("Object[%d].FilePermission = %v, want %v", i, got.Objects[i].FilePermission, want.Objects[i].FilePermission)
			}
			if len(got.Objects[i].Paths) != len(want.Objects[i].Paths) {
				t.Errorf("Object[%d].Paths length = %v, want %v", i, len(got.Objects[i].Paths), len(want.Objects[i].Paths))
			}
			for j := range got.Objects[i].Paths {
				if j < len(want.Objects[i].Paths) && got.Objects[i].Paths[j] != want.Objects[i].Paths[j] {
					t.Errorf("Object[%d].Paths[%d] = %v, want %v", i, j, got.Objects[i].Paths[j], want.Objects[i].Paths[j])
				}
			}
			if len(got.Objects[i].Audience) != len(want.Objects[i].Audience) {
				t.Errorf("Object[%d].Audience length = %v, want %v", i, len(got.Objects[i].Audience), len(want.Objects[i].Audience))
			}
			for j := range got.Objects[i].Audience {
				if j < len(want.Objects[i].Audience) && got.Objects[i].Audience[j] != want.Objects[i].Audience[j] {
					t.Errorf("Object[%d].Audience[%d] = %v, want %v", i, j, got.Objects[i].Audience[j], want.Objects[i].Audience[j])
				}
			}
		}
	}
}

func TestObjectFilePermission(t *testing.T) {
	tests := []struct {
		name     string
		object   Object
		expected os.FileMode
	}{
		{
			name: "default permission",
			object: Object{
				ObjectName: "test",
				Type:       "x509-svid",
				Paths:      []string{"/test"},
			},
			expected: 0,
		},
		{
			name: "custom permission 0600",
			object: Object{
				ObjectName:     "test",
				Type:           "x509-svid",
				FilePermission: 0600,
				Paths:          []string{"/test"},
			},
			expected: 0600,
		},
		{
			name: "custom permission 0644",
			object: Object{
				ObjectName:     "test",
				Type:           "x509-svid",
				FilePermission: 0644,
				Paths:          []string{"/test"},
			},
			expected: 0644,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.object.FilePermission != tt.expected {
				t.Errorf("FilePermission = %v, want %v", tt.object.FilePermission, tt.expected)
			}
		})
	}
}
