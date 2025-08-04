package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"spire-csi-provider/internal/client"
	"spire-csi-provider/internal/config"
	"spire-csi-provider/internal/hmac"
	"spire-csi-provider/internal/metrics"

	"github.com/hashicorp/go-hclog"
	typesapi "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

type Provider struct {
	logger        hclog.Logger
	hmacGenerator *hmac.HMACGenerator
	podContext    metrics.PodContext

	spireClient      client.SpireClient
	spireClientMutex sync.RWMutex
	clientConfig     client.Config
	clientPool       *client.ClientPool
}

func NewProviderWithContext(logger hclog.Logger, hmacGenerator *hmac.HMACGenerator, podContext metrics.PodContext) *Provider {
	return &Provider{
		logger:        logger,
		hmacGenerator: hmacGenerator,
		podContext:    podContext,
	}
}

func NewProviderWithClientPool(logger hclog.Logger, hmacGenerator *hmac.HMACGenerator, podContext metrics.PodContext, clientPool *client.ClientPool) *Provider {
	return &Provider{
		logger:        logger,
		hmacGenerator: hmacGenerator,
		podContext:    podContext,
		clientPool:    clientPool,
	}
}

func (p *Provider) HandleMountRequest(ctx context.Context, cfg config.Config, flagsConfig config.FlagsConfig) (*pb.MountResponse, error) {
	start := time.Now()

	socketPath := flagsConfig.SpireSocketPath
	if socketPath == "" {
		p.logger.Error("SPIRE socket path not specified")
		return nil, fmt.Errorf("SPIRE socket path not specified")
	}

	p.logger.Info("handling mount request",
		"target_path", cfg.TargetPath,
		"trust_domain", cfg.Parameters.TrustDomain,
		"object_count", len(cfg.Parameters.Objects),
		"socket_path", socketPath,
		"using_pool", p.clientPool != nil,
	)

	spiffeID := p.buildSpiffeIDFromSelectors(cfg.Parameters)
	p.logger.Debug("built SPIFFE ID from selectors", "spiffe_id", spiffeID)

	var spireClient client.SpireClient
	var releaseFunc func()
	var err error

	if p.clientPool != nil {
		clientConfig := client.Config{
			SpireSocketPath:   socketPath,
			SpireSocketPath2:  flagsConfig.SpireSocketPath2,
			SpiffeTrustDomain: cfg.Parameters.TrustDomain,
			Selectors:         convertConfigSelectorsToAPISelectors(cfg.Parameters.Selectors),
			RotatedQueueSize:  1024,
			PodContext:        p.podContext,
		}

		spireClient, err = p.clientPool.AcquireClient(ctx, clientConfig)
		if err != nil {
			p.logger.Error("failed to acquire SPIRE client from pool", "error", err)
			return nil, fmt.Errorf("failed to acquire SPIRE client from pool: %w", err)
		}

		releaseFunc = func() {
			p.clientPool.ReleaseClient(clientConfig)
		}
	} else {
		spireClient, err = p.getOrCreateSpireClient(ctx, socketPath, cfg.Parameters.TrustDomain, cfg.Parameters.Selectors, flagsConfig)
		if err != nil {
			p.logger.Error("failed to get SPIRE client", "error", err)
			return nil, fmt.Errorf("failed to get SPIRE client: %w", err)
		}
		releaseFunc = func() {} // No-op for non-pooled clients
	}

	defer releaseFunc()

	p.logger.Info("waiting for SVID and trust bundle",
		"spiffe_id", spiffeID,
		"timeout", "30s",
	)

	waitStart := time.Now()
	if err := spireClient.WaitForSVID(ctx, spiffeID, 30*time.Second); err != nil {
		p.logger.Error("failed waiting for SVID",
			"spiffe_id", spiffeID,
			"error", err,
			"wait_duration_ms", time.Since(waitStart).Milliseconds(),
		)
		return nil, fmt.Errorf("failed waiting for SVID: %w", err)
	}
	p.logger.Debug("SVID available",
		"spiffe_id", spiffeID,
		"wait_duration_ms", time.Since(waitStart).Milliseconds(),
	)

	bundleWaitStart := time.Now()
	if err := spireClient.WaitForTrustBundle(ctx, 30*time.Second); err != nil {
		p.logger.Error("failed waiting for trust bundle",
			"error", err,
			"wait_duration_ms", time.Since(bundleWaitStart).Milliseconds(),
		)
		return nil, fmt.Errorf("failed waiting for trust bundle: %w", err)
	}
	p.logger.Debug("trust bundle available",
		"wait_duration_ms", time.Since(bundleWaitStart).Milliseconds(),
	)

	var files []*pb.File
	var objectVersions []*pb.ObjectVersion

	for _, object := range cfg.Parameters.Objects {
		objectStart := time.Now()
		p.logger.Debug("processing object",
			"object_name", object.ObjectName,
			"type", object.Type,
			"paths", len(object.Paths),
			"file_permission", fmt.Sprintf("%o", object.FilePermission),
		)

		var contents map[string][]byte
		var err error

		switch object.Type {
		case "x509-svid":
			contents, err = p.fetchX509SVID(ctx, spireClient, object, spiffeID)
		case "jwt-svid":
			contents, err = p.fetchJWTSVID(ctx, spireClient, object, spiffeID)
		default:
			p.logger.Error("unsupported object type",
				"object_name", object.ObjectName,
				"type", object.Type,
			)
			metrics.RecordObjectProcessed(object.Type, "error_unsupported", p.podContext)
			return nil, fmt.Errorf("unsupported object type: %s", object.Type)
		}

		if err != nil {
			p.logger.Error("failed to fetch object",
				"object_name", object.ObjectName,
				"type", object.Type,
				"error", err,
				"duration_ms", time.Since(objectStart).Milliseconds(),
			)
			metrics.RecordObjectProcessed(object.Type, "error", p.podContext)
			return nil, fmt.Errorf("failed to fetch object %q: %w", object.ObjectName, err)
		}

		var combinedContent []byte
		for _, path := range object.Paths {
			combinedContent = append(combinedContent, contents[path]...)
		}

		version, err := p.hmacGenerator.GenerateObjectVersion(object, combinedContent)
		if err != nil {
			p.logger.Error("failed to generate version for object",
				"object_name", object.ObjectName,
				"error", err,
			)
			metrics.RecordObjectProcessed(object.Type, "error_version", p.podContext)
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

			p.logger.Info("file created",
				"path", path,
				"size", len(contents[path]),
				"mode", fmt.Sprintf("%o", filePermission),
				"object_name", object.ObjectName,
				"type", object.Type,
			)
		}

		p.logger.Debug("object processed successfully",
			"object_name", object.ObjectName,
			"type", object.Type,
			"duration_ms", time.Since(objectStart).Milliseconds(),
			"version", version.Version,
		)
		metrics.RecordObjectProcessed(object.Type, "success", p.podContext)
	}

	duration := time.Since(start)
	p.logger.Info("mount request completed",
		"duration_ms", duration.Milliseconds(),
		"file_count", len(files),
		"object_count", len(objectVersions),
		"target_path", cfg.TargetPath,
	)

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
		p.logger.Warn("no selectors provided")
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
		spiffeID := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", params.TrustDomain, namespace, serviceAccount)
		p.logger.Debug("built SPIFFE ID",
			"trust_domain", params.TrustDomain,
			"namespace", namespace,
			"service_account", serviceAccount,
			"spiffe_id", spiffeID,
		)
		return spiffeID
	}

	p.logger.Warn("unable to build complete SPIFFE ID",
		"trust_domain", params.TrustDomain,
		"namespace", namespace,
		"service_account", serviceAccount,
	)
	return ""
}

func (p *Provider) fetchX509SVID(ctx context.Context, spireClient client.SpireClient, object config.Object, spiffeID string) (map[string][]byte, error) {
	start := time.Now()
	p.logger.Debug("fetching X509 SVID",
		"spiffe_id", spiffeID,
		"object_name", object.ObjectName,
	)

	tlsCert, err := spireClient.GetCertificateForIdentity(spiffeID)
	if err != nil {
		p.logger.Error("failed to get certificate",
			"spiffe_id", spiffeID,
			"error", err,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	if len(object.Paths) != 3 {
		p.logger.Error("invalid path count for X.509 SVID",
			"expected", 3,
			"actual", len(object.Paths),
			"object_name", object.ObjectName,
		)
		return nil, fmt.Errorf("expected 3 paths for X.509 SVID but got %d", len(object.Paths))
	}

	result := make(map[string][]byte)

	certPath := object.Paths[0]
	keyPath := object.Paths[1]
	bundlePath := object.Paths[2]

	var certPEM strings.Builder
	certCount := 0
	for i, certBytes := range tlsCert.Certificate {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			p.logger.Error("failed to parse certificate in chain",
				"error", err,
				"cert_index", i,
				"object_name", object.ObjectName,
			)
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certPEM.WriteString(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})))
		certCount++

		p.logger.Trace("added certificate to chain",
			"index", i,
			"subject", cert.Subject,
			"issuer", cert.Issuer,
			"not_before", cert.NotBefore,
			"not_after", cert.NotAfter,
			"is_ca", cert.IsCA,
			"serial_number", cert.SerialNumber.String(),
		)
	}
	result[certPath] = []byte(certPEM.String())
	p.logger.Debug("certificate chain created",
		"path", certPath,
		"cert_count", certCount,
		"size", len(result[certPath]),
	)

	privateKey := tlsCert.PrivateKey
	keyStart := time.Now()

	pkBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		p.logger.Error("failed to marshal private key",
			"error", err,
			"object_name", object.ObjectName,
		)
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkBytes,
	})
	result[keyPath] = keyBytes
	p.logger.Debug("private key created",
		"path", keyPath,
		"size", len(result[keyPath]),
		"duration_ms", time.Since(keyStart).Milliseconds(),
		"key_type", fmt.Sprintf("%T", privateKey),
	)

	bundleStart := time.Now()
	var bundlePEM strings.Builder

	certs, err := spireClient.GetCACertificates(ctx)
	if err != nil {
		p.logger.Error("failed to get CA certificates",
			"error", err,
			"object_name", object.ObjectName,
			"duration_ms", time.Since(bundleStart).Milliseconds(),
		)
		return nil, fmt.Errorf("failed to get certificates from trust bundle: %w", err)
	}

	bundleCertCount := 0
	for i, cert := range certs {
		bundlePEM.WriteString(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})))
		bundleCertCount++

		p.logger.Trace("added CA certificate to bundle",
			"index", i,
			"subject", cert.Subject,
			"issuer", cert.Issuer,
			"not_after", cert.NotAfter,
			"is_ca", cert.IsCA,
		)
	}

	result[bundlePath] = []byte(bundlePEM.String())
	p.logger.Debug("trust bundle created",
		"path", bundlePath,
		"cert_count", bundleCertCount,
		"size", len(result[bundlePath]),
		"duration_ms", time.Since(bundleStart).Milliseconds(),
	)

	totalDuration := time.Since(start)
	p.logger.Info("X509 SVID fetched successfully",
		"object_name", object.ObjectName,
		"spiffe_id", spiffeID,
		"cert_count", certCount,
		"bundle_cert_count", bundleCertCount,
		"total_duration_ms", totalDuration.Milliseconds(),
		"total_size", len(result[certPath])+len(result[keyPath])+len(result[bundlePath]),
	)

	return result, nil
}

func (p *Provider) getOrCreateSpireClient(ctx context.Context, socketPath string, trustDomain string, selectors []config.Selector, flagsConfig config.FlagsConfig) (client.SpireClient, error) {
	p.spireClientMutex.RLock()
	if p.spireClient != nil {
		// Check if the configuration matches
		if p.clientConfig.SpireSocketPath == socketPath &&
			p.clientConfig.SpiffeTrustDomain == trustDomain {
			p.spireClientMutex.RUnlock()
			p.logger.Debug("reusing existing SPIRE client")
			return p.spireClient, nil
		}
		p.spireClientMutex.RUnlock()

		p.logger.Info("SPIRE client configuration changed, recreating client")
		p.stopSpireClient()
	} else {
		p.spireClientMutex.RUnlock()
	}

	p.spireClientMutex.Lock()
	defer p.spireClientMutex.Unlock()

	if p.spireClient != nil {
		return p.spireClient, nil
	}

	clientConfig := client.Config{
		SpireSocketPath:   socketPath,
		SpireSocketPath2:  flagsConfig.SpireSocketPath2,
		SpiffeTrustDomain: trustDomain,
		Selectors:         convertConfigSelectorsToAPISelectors(selectors),
		RotatedQueueSize:  1024,
		PodContext:        p.podContext,
	}

	spireClient, err := client.NewSpireClient(p.logger.Named("spire-client"), clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create SPIRE client: %w", err)
	}

	err = spireClient.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start SPIRE client: %w", err)
	}

	p.spireClient = spireClient
	p.clientConfig = clientConfig
	p.logger.Info("created new SPIRE client")

	return spireClient, nil
}

func (p *Provider) stopSpireClient() {
	p.spireClientMutex.Lock()
	defer p.spireClientMutex.Unlock()

	if p.spireClient != nil {
		p.logger.Info("stopping SPIRE client")
		p.spireClient.Stop()
		p.spireClient = nil
	}
}

func (p *Provider) Stop() error {
	p.stopSpireClient()
	return nil
}

func (p *Provider) fetchJWTSVID(ctx context.Context, spireClient client.SpireClient, object config.Object, spiffeID string) (map[string][]byte, error) {
	start := time.Now()
	p.logger.Debug("fetching JWT SVID",
		"spiffe_id", spiffeID,
		"object_name", object.ObjectName,
		"audiences", object.Audience,
		"audience_count", len(object.Audience),
	)

	if len(object.Audience) == 0 {
		p.logger.Error("no audience specified for JWT SVID",
			"object_name", object.ObjectName,
		)
		return nil, fmt.Errorf("no audience specified for JWT SVID")
	}

	if len(object.Paths) != 1 {
		p.logger.Error("invalid path count for JWT SVID",
			"expected", 1,
			"actual", len(object.Paths),
			"object_name", object.ObjectName,
		)
		return nil, fmt.Errorf("expected 1 path for JWT SVID but got %d", len(object.Paths))
	}

	token, err := spireClient.FetchJWTSVID(ctx, spiffeID, object.Audience)
	if err != nil {
		p.logger.Error("failed to fetch JWT SVID",
			"spiffe_id", spiffeID,
			"audiences", object.Audience,
			"error", err,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, fmt.Errorf("failed to fetch JWT SVID: %w", err)
	}

	result := make(map[string][]byte)
	result[object.Paths[0]] = []byte(token)

	p.logger.Debug("JWT token details",
		"token_size", len(token),
		"has_header", strings.HasPrefix(token, "eyJ"),
		"part_count", len(strings.Split(token, ".")),
	)

	duration := time.Since(start)
	p.logger.Info("JWT SVID fetched successfully",
		"object_name", object.ObjectName,
		"spiffe_id", spiffeID,
		"audiences", object.Audience,
		"token_size", len(token),
		"path", object.Paths[0],
		"duration_ms", duration.Milliseconds(),
	)

	return result, nil
}
