// internal/version/version_test.go
package version

import (
	"encoding/json"
	"testing"
)

func TestGetVersion(t *testing.T) {
	// Set test values
	BuildVersion = "v1.2.3"
	BuildDate = "2024-01-01"
	GoVersion = "1.21"

	versionStr, err := GetVersion()
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}

	var pv providerVersion
	if err := json.Unmarshal([]byte(versionStr), &pv); err != nil {
		t.Fatalf("Failed to unmarshal version JSON: %v", err)
	}

	if pv.Version != BuildVersion {
		t.Errorf("Version = %v, want %v", pv.Version, BuildVersion)
	}
	if pv.BuildDate != BuildDate {
		t.Errorf("BuildDate = %v, want %v", pv.BuildDate, BuildDate)
	}
	if pv.GoVersion != GoVersion {
		t.Errorf("GoVersion = %v, want %v", pv.GoVersion, GoVersion)
	}
	if pv.MinDriverVersion != minDriverVersion {
		t.Errorf("MinDriverVersion = %v, want %v", pv.MinDriverVersion, minDriverVersion)
	}
}

func TestGetVersion_EmptyValues(t *testing.T) {
	// Reset to empty values
	BuildVersion = ""
	BuildDate = ""
	GoVersion = ""

	versionStr, err := GetVersion()
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}

	var pv providerVersion
	if err := json.Unmarshal([]byte(versionStr), &pv); err != nil {
		t.Fatalf("Failed to unmarshal version JSON: %v", err)
	}

	if pv.Version != "" {
		t.Errorf("Expected empty Version, got %v", pv.Version)
	}
	if pv.MinDriverVersion != minDriverVersion {
		t.Errorf("MinDriverVersion should always be %v, got %v", minDriverVersion, pv.MinDriverVersion)
	}
}

func TestMinDriverVersion(t *testing.T) {
	if minDriverVersion != "v0.0.1" {
		t.Errorf("minDriverVersion = %v, want v0.0.1", minDriverVersion)
	}
}
