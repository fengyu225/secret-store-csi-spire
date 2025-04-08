package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/go-hclog"
	typesapi "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
	"spire-csi-provider/internal/client"
	"spire-csi-provider/internal/config"
	"spire-csi-provider/internal/hmac"
	"strings"
	"time"
)

type Provider struct {
	logger hclog.Logger

	hmacGenerator *hmac.HMACGenerator
}

func NewProvider(logger hclog.Logger, hmacGenerator *hmac.HMACGenerator) *Provider {
	return &Provider{
		logger:        logger,
		hmacGenerator: hmacGenerator,
	}
}

func (p *Provider) HandleMountRequest(ctx context.Context, cfg config.Config, flagsConfig config.FlagsConfig) (*pb.MountResponse, error) {
	socketPath := flagsConfig.SpireSocketPath
	if socketPath == "" {
		return nil, fmt.Errorf("SPIRE socket path not specified")
	}

	clientConfig := client.Config{
		SpireSocketPath:   socketPath,
		SpiffeTrustDomain: cfg.Parameters.TrustDomain,
		Selectors:         convertConfigSelectorsToAPISelectors(cfg.Parameters.Selectors),
		RotatedQueueSize:  1024,
	}

	spireClient, err := client.New(p.logger.Named("spire-client"), clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create SPIRE client: %w", err)
	}

	err = spireClient.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start SPIRE client: %w", err)
	}
	defer spireClient.Stop()

	var files []*pb.File
	var objectVersions []*pb.ObjectVersion

	for _, object := range cfg.Parameters.Objects {
		var contents map[string][]byte
		var err error

		spiffeID := p.buildSpiffeIDFromSelectors(cfg.Parameters)

		// TODO: wait for SVID being fetched
		time.Sleep(5 * time.Second)

		switch object.Type {
		case "x509-svid":
			contents, err = p.fetchX509SVID(ctx, spireClient, object, spiffeID)
		case "jwt-svid":
			contents, err = p.fetchJWTSVID(ctx, spireClient, object, spiffeID)
		default:
			return nil, fmt.Errorf("unsupported object type: %s", object.Type)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to fetch object %q: %w", object.ObjectName, err)
		}

		var combinedContent []byte
		for _, path := range object.Paths {
			combinedContent = append(combinedContent, contents[path]...)
		}

		version, err := p.hmacGenerator.GenerateObjectVersion(object, combinedContent)
		if err != nil {
			return nil, fmt.Errorf("failed to generate version for object %q: %w", object.ObjectName, err)
		}
		objectVersions = append(objectVersions, version)

		filePermission := int32(cfg.FilePermission)
		if object.FilePermission != 0 {
			filePermission = int32(object.FilePermission)
		}

		for _, path := range object.Paths {
			files = append(files, &pb.File{
				Path:     path,
				Mode:     filePermission,
				Contents: contents[path],
			})

			p.logger.Info("file added to mount response",
				"directory", cfg.TargetPath,
				"file", path,
				"objectName", object.ObjectName,
				"type", object.Type)
		}
	}

	return &pb.MountResponse{
		Files:         files,
		ObjectVersion: objectVersions,
	}, nil
}

func convertConfigSelectorsToAPISelectors(configSelectors []config.Selector) []*typesapi.Selector {
	selectors := make([]*typesapi.Selector, len(configSelectors))
	for i, selector := range configSelectors {
		selectors[i] = &typesapi.Selector{
			Type:  selector.Type,
			Value: selector.Value,
		}
	}
	return selectors
}

func (p *Provider) buildSpiffeIDFromSelectors(params config.Parameters) string {
	if len(params.Selectors) == 0 {
		return ""
	}

	var namespace, serviceAccount string
	for _, selector := range params.Selectors {
		if selector.Type == "k8s" {
			if strings.HasPrefix(selector.Value, "ns:") {
				namespace = strings.TrimPrefix(selector.Value, "ns:")
			} else if strings.HasPrefix(selector.Value, "sa:") {
				serviceAccount = strings.TrimPrefix(selector.Value, "sa:")
			}
		}
	}

	if namespace != "" && serviceAccount != "" && params.TrustDomain != "" {
		return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", params.TrustDomain, namespace, serviceAccount)
	}

	return ""
}

func (p *Provider) fetchX509SVID(ctx context.Context, spireClient *client.Client, object config.Object, spiffeID string) (map[string][]byte, error) {
	tlsCert, err := spireClient.GetCertificateForIdentity(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	if len(object.Paths) != 3 {
		return nil, fmt.Errorf("expected 3 paths for X.509 SVID but got %d", len(object.Paths))
	}

	result := make(map[string][]byte)

	certPath := object.Paths[0]
	keyPath := object.Paths[1]
	bundlePath := object.Paths[2]

	var certPEM strings.Builder
	for _, certBytes := range tlsCert.Certificate {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certPEM.WriteString(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})))
	}
	result[certPath] = []byte(certPEM.String())

	privateKey := tlsCert.PrivateKey

	pkBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkBytes,
	})
	result[keyPath] = keyBytes

	var bundlePEM strings.Builder

	certs, err := spireClient.GetCACertificates(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificates from trust bundle: %w", err)
	}

	for _, cert := range certs {
		bundlePEM.WriteString(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})))
	}

	result[bundlePath] = []byte(bundlePEM.String())

	return result, nil
}

func (p *Provider) fetchJWTSVID(ctx context.Context, spireClient *client.Client, object config.Object, spiffeID string) (map[string][]byte, error) {
	if len(object.Audience) == 0 {
		return nil, fmt.Errorf("no audience specified for JWT SVID")
	}

	if len(object.Paths) != 1 {
		return nil, fmt.Errorf("expected 1 path for JWT SVID but got %d", len(object.Paths))
	}

	token, err := spireClient.FetchJWTSVID(ctx, spiffeID, object.Audience)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWT SVID: %w", err)
	}

	result := make(map[string][]byte)
	result[object.Paths[0]] = []byte(token)

	return result, nil
}
