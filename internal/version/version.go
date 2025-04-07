package version

import (
	"encoding/json"
)

const minDriverVersion = "v0.0.1"

var (
	BuildDate string

	BuildVersion string

	GoVersion string
)

type providerVersion struct {
	Version          string `json:"version"`
	BuildDate        string `json:"buildDate"`
	GoVersion        string `json:"goVersion"`
	MinDriverVersion string `json:"minDriverVersion"`
}

func GetVersion() (string, error) {
	pv := providerVersion{
		Version:          BuildVersion,
		BuildDate:        BuildDate,
		GoVersion:        GoVersion,
		MinDriverVersion: minDriverVersion,
	}

	res, err := json.Marshal(pv)
	if err != nil {
		return "", err
	}

	return string(res), nil
}
