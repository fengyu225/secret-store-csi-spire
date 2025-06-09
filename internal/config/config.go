package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/types"
)

type Config struct {
	Parameters     Parameters
	TargetPath     string
	FilePermission os.FileMode
}

type FlagsConfig struct {
	Endpoint        string
	LogLevel        string
	Version         bool
	HealthAddr      string
	HMACSecretName  string
	CacheSize       int
	SpireSocketPath string
	MetricsAddr     string
}

type Parameters struct {
	UseCase     string
	TrustDomain string
	Selectors   []Selector
	Rotation    RotationConfig
	Objects     []Object
	PodInfo     PodInfo
}

type Selector struct {
	Type  string `yaml:"type,omitempty"`
	Value string `yaml:"value,omitempty"`
}

type RotationConfig struct {
	Enabled      bool
	PollInterval time.Duration
	RenewBefore  time.Duration
}

type Object struct {
	ObjectName     string      `yaml:"objectName,omitempty"`
	Type           string      `yaml:"type,omitempty"`
	Audience       []string    `yaml:"audience,omitempty"`
	FilePermission os.FileMode `yaml:"filePermission,omitempty"`
	Paths          []string    `yaml:"paths,omitempty"`
}

type PodInfo struct {
	Name               string
	UID                types.UID
	Namespace          string
	ServiceAccountName string
}

func Parse(parametersStr, targetPath, permissionStr string) (Config, error) {
	config := Config{
		TargetPath: targetPath,
	}

	var err error
	config.Parameters, err = parseParameters(parametersStr)
	if err != nil {
		return Config{}, err
	}

	if err := json.Unmarshal([]byte(permissionStr), &config.FilePermission); err != nil {
		return Config{}, err
	}

	if err := config.validate(); err != nil {
		return Config{}, err
	}

	return config, nil
}

func parseParameters(parametersStr string) (Parameters, error) {
	var params map[string]string
	err := json.Unmarshal([]byte(parametersStr), &params)
	if err != nil {
		return Parameters{}, err
	}

	var parameters Parameters

	parameters.UseCase = params["useCase"]
	parameters.TrustDomain = params["trustDomain"]

	parameters.PodInfo.Name = params["csi.storage.k8s.io/pod.name"]
	parameters.PodInfo.UID = types.UID(params["csi.storage.k8s.io/pod.uid"])
	parameters.PodInfo.Namespace = params["csi.storage.k8s.io/pod.namespace"]
	parameters.PodInfo.ServiceAccountName = params["csi.storage.k8s.io/serviceAccount.name"]

	parameters.Selectors = []Selector{
		{
			Type:  "k8s",
			Value: fmt.Sprintf("ns:%s", parameters.PodInfo.Namespace),
		},
		{
			Type:  "k8s",
			Value: fmt.Sprintf("sa:%s", parameters.PodInfo.ServiceAccountName),
		},
		{
			Type:  "k8s",
			Value: fmt.Sprintf("pod-uid:%s", parameters.PodInfo.UID),
		},
	}

	objectsYaml := params["objects"]
	if objectsYaml != "" {
		err = yaml.Unmarshal([]byte(objectsYaml), &parameters.Objects)
		if err != nil {
			return Parameters{}, fmt.Errorf("failed to parse objects: %w", err)
		}
	}

	return parameters, nil
}

func (c *Config) validate() error {

	if c.TargetPath == "" {
		return errors.New("missing target path field")
	}

	if len(c.Parameters.Objects) == 0 {
		return errors.New("no objects configured - the provider will not fetch any SPIRE SVIDs")
	}

	objectNames := map[string]struct{}{}
	duplicates := []string{}

	for _, object := range c.Parameters.Objects {
		if _, exists := objectNames[object.ObjectName]; exists {
			duplicates = append(duplicates, object.ObjectName)
		}
		objectNames[object.ObjectName] = struct{}{}

		switch object.Type {
		case "x509-svid", "jwt-svid":

		default:
			return fmt.Errorf("invalid type %q for object %q", object.Type, object.ObjectName)
		}

		if object.Type == "jwt-svid" && len(object.Audience) == 0 {
			return fmt.Errorf("audience is required for JWT SVID object %q", object.ObjectName)
		}

		if len(object.Paths) == 0 {
			return fmt.Errorf("no paths defined for object %q", object.ObjectName)
		}

		if object.Type == "x509-svid" && len(object.Paths) != 3 {
			return fmt.Errorf("x509-svid object %q should have exactly 3 paths (cert, key, bundle)", object.ObjectName)
		}

		if object.Type == "jwt-svid" && len(object.Paths) != 1 {
			return fmt.Errorf("jwt-svid object %q should have exactly 1 path", object.ObjectName)
		}
	}

	if len(duplicates) > 0 {
		return fmt.Errorf("each 'objectName' within a SecretProviderClass must be unique")
	}

	for _, selector := range c.Parameters.Selectors {
		if selector.Type == "" {
			return errors.New("selector type cannot be empty")
		}
		if selector.Value == "" {
			return errors.New("selector value cannot be empty")
		}
	}

	return nil
}
